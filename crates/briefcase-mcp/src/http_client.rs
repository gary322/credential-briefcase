use std::time::Duration;

use anyhow::Context as _;
use http::header::CONTENT_TYPE;
use reqwest::StatusCode;
use serde_json::Value;
use tracing::debug;
use url::Url;
use uuid::Uuid;

use crate::PROTOCOL_VERSION_LATEST;
use crate::jsonrpc::{JsonRpcId, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};
use crate::server::McpConnection;
use crate::sse::parse_first_json_message_from_sse;
use crate::types::{
    CallToolParams, CallToolResult, InitializeParams, InitializeResult, ListToolsParams,
    ListToolsResult,
};

#[derive(Debug, Clone)]
pub struct HttpMcpClientOptions {
    pub endpoint: Url,
    pub protocol_version: String,
    pub session_id: Option<String>,
    pub timeout: Duration,
}

impl HttpMcpClientOptions {
    pub fn new(endpoint: Url) -> Self {
        Self {
            endpoint,
            protocol_version: PROTOCOL_VERSION_LATEST.to_string(),
            session_id: None,
            timeout: Duration::from_secs(30),
        }
    }
}

/// MCP client over Streamable HTTP transport.
#[derive(Clone)]
pub struct HttpMcpClient {
    http: reqwest::Client,
    endpoint: Url,
    protocol_version: String,
    session_id: Option<String>,
    initialized: bool,
    ready: bool,
}

impl HttpMcpClient {
    pub fn new(opts: HttpMcpClientOptions) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(opts.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            http,
            endpoint: opts.endpoint,
            protocol_version: opts.protocol_version,
            session_id: opts.session_id,
            initialized: false,
            ready: false,
        })
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub async fn initialize(
        &mut self,
        client_name: &str,
        client_version: &str,
    ) -> anyhow::Result<InitializeResult> {
        if self.initialized {
            anyhow::bail!("already initialized");
        }

        let params = InitializeParams::new_default(client_name, client_version);
        let id = JsonRpcId::String(Uuid::new_v4().to_string());
        let req = JsonRpcRequest::new(
            id.clone(),
            "initialize",
            Some(serde_json::to_value(params)?),
        );

        let (resp, session_id) = self.send_request(req).await?;
        if let Some(sid) = session_id {
            self.session_id = Some(sid);
        }

        let init: InitializeResult = parse_result(resp)?;
        self.protocol_version = init.protocol_version.clone();
        self.initialized = true;

        // Complete lifecycle handshake.
        let notif = JsonRpcMessage::Notification(McpConnection::make_initialized_notification());
        self.send_notification(notif).await?;
        self.ready = true;

        Ok(init)
    }

    pub async fn list_tools(&mut self, params: ListToolsParams) -> anyhow::Result<ListToolsResult> {
        self.ensure_ready()?;
        let id = JsonRpcId::String(Uuid::new_v4().to_string());
        let req = JsonRpcRequest::new(id, "tools/list", Some(serde_json::to_value(params)?));
        let (resp, _) = self.send_request(req).await?;
        parse_result::<ListToolsResult>(resp)
    }

    pub async fn call_tool(&mut self, params: CallToolParams) -> anyhow::Result<CallToolResult> {
        self.ensure_ready()?;
        let id = JsonRpcId::String(Uuid::new_v4().to_string());
        let req = JsonRpcRequest::new(id, "tools/call", Some(serde_json::to_value(params)?));
        let (resp, _) = self.send_request(req).await?;
        parse_result::<CallToolResult>(resp)
    }

    fn ensure_ready(&self) -> anyhow::Result<()> {
        if !self.ready {
            anyhow::bail!("mcp client not ready (missing initialize)");
        }
        Ok(())
    }

    async fn send_notification(&self, msg: JsonRpcMessage) -> anyhow::Result<()> {
        let mut req = self
            .http
            .post(self.endpoint.clone())
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", &self.protocol_version)
            .json(&msg);

        if let Some(sid) = &self.session_id {
            req = req.header("mcp-session-id", sid);
        }

        let resp = req.send().await.context("send notification")?;
        if resp.status() == StatusCode::ACCEPTED {
            return Ok(());
        }
        if resp.status().is_success() {
            // Some servers may respond with a JSON-RPC response even for notifications.
            return Ok(());
        }
        anyhow::bail!("notification failed: {}", resp.status());
    }

    async fn send_request(
        &self,
        req_msg: JsonRpcRequest,
    ) -> anyhow::Result<(JsonRpcResponse, Option<String>)> {
        let mut req = self
            .http
            .post(self.endpoint.clone())
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", &self.protocol_version)
            .json(&req_msg);

        if let Some(sid) = &self.session_id {
            req = req.header("mcp-session-id", sid);
        }

        let resp = req.send().await.context("send request")?;
        let status = resp.status();
        let session_id = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        if status == StatusCode::ACCEPTED {
            anyhow::bail!("server returned 202 accepted for a request (no response)");
        }
        if !status.is_success() {
            anyhow::bail!("mcp http status {status}");
        }

        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        let body = resp.text().await.context("read response body")?;
        debug!(content_type = %ct, "mcp http response");

        let json = if ct.starts_with("application/json") || ct.is_empty() {
            serde_json::from_str::<Value>(&body).context("parse application/json")?
        } else if ct.starts_with("text/event-stream") {
            parse_first_json_message_from_sse(&body)?
        } else {
            anyhow::bail!("unsupported content-type: {ct}");
        };

        let msg: JsonRpcMessage = serde_json::from_value(json).context("parse json-rpc")?;
        let JsonRpcMessage::Response(r) = msg else {
            anyhow::bail!("expected json-rpc response");
        };
        Ok((r, session_id))
    }
}

fn parse_result<T: serde::de::DeserializeOwned>(resp: JsonRpcResponse) -> anyhow::Result<T> {
    if resp.jsonrpc != "2.0" {
        anyhow::bail!("invalid jsonrpc version in response");
    }
    if let Some(err) = resp.error {
        anyhow::bail!("mcp json-rpc error {}: {}", err.code, err.message);
    }
    let Some(v) = resp.result else {
        anyhow::bail!("missing result");
    };
    serde_json::from_value(v).context("decode result")
}
