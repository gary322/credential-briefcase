#[cfg(unix)]
use std::path::PathBuf;

use anyhow::Context as _;
use bytes::Bytes;
use http::{Method, Request, Uri};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::types::{
    ApproveResponse, BudgetRecord, CallToolRequest, CallToolResponse, DeleteMcpServerResponse,
    DeleteProviderResponse, ErrorResponse, FetchVcResponse, IdentityResponse,
    ListApprovalsResponse, ListBudgetsResponse, ListMcpServersResponse, ListProvidersResponse,
    ListReceiptsResponse, ListToolsResponse, McpOAuthExchangeRequest, McpOAuthExchangeResponse,
    McpOAuthStartRequest, McpOAuthStartResponse, McpServerSummary, OAuthExchangeRequest,
    OAuthExchangeResponse, ProviderSummary, SetBudgetRequest, UpsertMcpServerRequest,
    UpsertProviderRequest, VerifyReceiptsResponse,
};

#[derive(Debug, Clone)]
pub enum DaemonEndpoint {
    Tcp {
        base_url: String,
    },
    #[cfg(unix)]
    Unix {
        socket_path: PathBuf,
    },
}

#[derive(Debug, Clone)]
pub struct BriefcaseClient {
    endpoint: DaemonEndpoint,
    auth_token: String,
}

#[derive(Debug, Error)]
pub enum BriefcaseClientError {
    #[error("invalid uri: {0}")]
    Uri(#[from] http::uri::InvalidUri),
    #[error("http error: {0}")]
    Http(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("daemon error {code}: {message}")]
    Daemon { code: String, message: String },
    #[error("other error: {0}")]
    Other(#[from] anyhow::Error),
}

impl BriefcaseClient {
    pub fn new(endpoint: DaemonEndpoint, auth_token: String) -> Self {
        Self {
            endpoint,
            auth_token,
        }
    }

    pub async fn health(&self) -> Result<(), BriefcaseClientError> {
        let _: serde_json::Value = self.get_json("/health").await?;
        Ok(())
    }

    pub async fn list_tools(&self) -> Result<ListToolsResponse, BriefcaseClientError> {
        self.get_json("/v1/tools").await
    }

    pub async fn identity(&self) -> Result<IdentityResponse, BriefcaseClientError> {
        self.get_json("/v1/identity").await
    }

    pub async fn list_providers(&self) -> Result<ListProvidersResponse, BriefcaseClientError> {
        self.get_json("/v1/providers").await
    }

    pub async fn upsert_provider(
        &self,
        provider_id: &str,
        base_url: String,
    ) -> Result<ProviderSummary, BriefcaseClientError> {
        self.post_json(
            &format!("/v1/providers/{provider_id}"),
            UpsertProviderRequest { base_url },
        )
        .await
    }

    pub async fn delete_provider(
        &self,
        provider_id: &str,
    ) -> Result<DeleteProviderResponse, BriefcaseClientError> {
        self.post_json(
            &format!("/v1/providers/{provider_id}/delete"),
            serde_json::json!({}),
        )
        .await
    }

    pub async fn list_mcp_servers(&self) -> Result<ListMcpServersResponse, BriefcaseClientError> {
        self.get_json("/v1/mcp/servers").await
    }

    pub async fn upsert_mcp_server(
        &self,
        server_id: &str,
        endpoint_url: String,
    ) -> Result<McpServerSummary, BriefcaseClientError> {
        self.post_json(
            &format!("/v1/mcp/servers/{server_id}"),
            UpsertMcpServerRequest { endpoint_url },
        )
        .await
    }

    pub async fn delete_mcp_server(
        &self,
        server_id: &str,
    ) -> Result<DeleteMcpServerResponse, BriefcaseClientError> {
        self.post_json(
            &format!("/v1/mcp/servers/{server_id}/delete"),
            serde_json::json!({}),
        )
        .await
    }

    pub async fn mcp_oauth_start(
        &self,
        server_id: &str,
        req: McpOAuthStartRequest,
    ) -> Result<McpOAuthStartResponse, BriefcaseClientError> {
        self.post_json(&format!("/v1/mcp/servers/{server_id}/oauth/start"), req)
            .await
    }

    pub async fn mcp_oauth_exchange(
        &self,
        server_id: &str,
        req: McpOAuthExchangeRequest,
    ) -> Result<McpOAuthExchangeResponse, BriefcaseClientError> {
        self.post_json(&format!("/v1/mcp/servers/{server_id}/oauth/exchange"), req)
            .await
    }

    pub async fn list_budgets(&self) -> Result<ListBudgetsResponse, BriefcaseClientError> {
        self.get_json("/v1/budgets").await
    }

    pub async fn set_budget(
        &self,
        category: &str,
        daily_limit_microusd: i64,
    ) -> Result<BudgetRecord, BriefcaseClientError> {
        self.post_json(
            &format!("/v1/budgets/{category}"),
            SetBudgetRequest {
                daily_limit_microusd,
            },
        )
        .await
    }

    pub async fn oauth_exchange(
        &self,
        provider_id: &str,
        req: OAuthExchangeRequest,
    ) -> Result<OAuthExchangeResponse, BriefcaseClientError> {
        self.post_json(&format!("/v1/providers/{provider_id}/oauth/exchange"), req)
            .await
    }

    pub async fn fetch_vc(
        &self,
        provider_id: &str,
    ) -> Result<FetchVcResponse, BriefcaseClientError> {
        self.post_json(
            &format!("/v1/providers/{provider_id}/vc/fetch"),
            serde_json::json!({}),
        )
        .await
    }

    pub async fn call_tool(
        &self,
        req: CallToolRequest,
    ) -> Result<CallToolResponse, BriefcaseClientError> {
        self.post_json("/v1/tools/call", req).await
    }

    pub async fn list_approvals(&self) -> Result<ListApprovalsResponse, BriefcaseClientError> {
        self.get_json("/v1/approvals").await
    }

    pub async fn approve(&self, id: &uuid::Uuid) -> Result<ApproveResponse, BriefcaseClientError> {
        self.post_json(
            &format!("/v1/approvals/{id}/approve"),
            serde_json::json!({}),
        )
        .await
    }

    pub async fn list_receipts(&self) -> Result<ListReceiptsResponse, BriefcaseClientError> {
        self.get_json("/v1/receipts?limit=50&offset=0").await
    }

    pub async fn verify_receipts(&self) -> Result<VerifyReceiptsResponse, BriefcaseClientError> {
        self.post_json("/v1/receipts/verify", serde_json::json!({}))
            .await
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, BriefcaseClientError> {
        self.send_json(Method::GET, path, Option::<serde_json::Value>::None)
            .await
    }

    async fn post_json<Req: Serialize, Res: DeserializeOwned>(
        &self,
        path: &str,
        body: Req,
    ) -> Result<Res, BriefcaseClientError> {
        self.send_json(Method::POST, path, Some(body)).await
    }

    async fn send_json<Req: Serialize, Res: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Req>,
    ) -> Result<Res, BriefcaseClientError> {
        let body_bytes = match body {
            Some(b) => serde_json::to_vec(&b)?,
            None => Vec::new(),
        };

        let req = self.build_request(method, path, body_bytes)?;
        let resp_bytes = self.send(req).await?;

        Ok(serde_json::from_slice(&resp_bytes)?)
    }

    fn build_request(
        &self,
        method: Method,
        path: &str,
        body: Vec<u8>,
    ) -> Result<Request<Full<Bytes>>, BriefcaseClientError> {
        let uri: Uri = match &self.endpoint {
            DaemonEndpoint::Tcp { base_url } => format!("{base_url}{path}").parse()?,
            #[cfg(unix)]
            DaemonEndpoint::Unix { socket_path } => {
                let u = hyperlocal::Uri::new(socket_path, path);
                u.into()
            }
        };

        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("accept", "application/json")
            .header("authorization", format!("Bearer {}", self.auth_token));

        if !body.is_empty() {
            builder = builder.header("content-type", "application/json");
        }

        builder
            .body(Full::new(Bytes::from(body)))
            .context("build http request")
            .map_err(BriefcaseClientError::Other)
    }

    async fn send(&self, req: Request<Full<Bytes>>) -> Result<Vec<u8>, BriefcaseClientError> {
        let resp = match &self.endpoint {
            DaemonEndpoint::Tcp { .. } => {
                let mut connector = HttpConnector::new();
                connector.enforce_http(false);
                let client: Client<_, Full<Bytes>> =
                    Client::builder(TokioExecutor::new()).build(connector);
                client
                    .request(req)
                    .await
                    .map_err(|e| BriefcaseClientError::Http(e.to_string()))?
            }
            #[cfg(unix)]
            DaemonEndpoint::Unix { .. } => {
                let client: Client<_, Full<Bytes>> =
                    Client::builder(TokioExecutor::new()).build(hyperlocal::UnixConnector);
                client
                    .request(req)
                    .await
                    .map_err(|e| BriefcaseClientError::Http(e.to_string()))?
            }
        };

        let status = resp.status();
        let body = collect_body(resp.into_body()).await?;

        if !status.is_success() {
            if let Ok(err) = serde_json::from_slice::<ErrorResponse>(&body) {
                return Err(BriefcaseClientError::Daemon {
                    code: err.code,
                    message: err.message,
                });
            }
            return Err(BriefcaseClientError::Http(format!(
                "unexpected status={status}, body={}",
                String::from_utf8_lossy(&body)
            )));
        }

        Ok(body)
    }
}

async fn collect_body(body: Incoming) -> Result<Vec<u8>, BriefcaseClientError> {
    use http_body_util::BodyExt as _;
    let collected = body
        .collect()
        .await
        .map_err(|e| BriefcaseClientError::Http(e.to_string()))?;
    Ok(collected.to_bytes().to_vec())
}
