use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::jsonrpc::{
    JsonRpcError, JsonRpcId, JsonRpcMessage, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
};
use crate::types::{
    CallToolParams, CallToolResult, InitializeParams, InitializeResult, ListToolsParams,
    ListToolsResult, McpServerInfo,
};
use crate::{PROTOCOL_VERSION_2025_06_18, PROTOCOL_VERSION_LATEST};

#[async_trait]
pub trait McpHandler: Send + Sync {
    async fn list_tools(&self, params: ListToolsParams) -> anyhow::Result<ListToolsResult>;
    async fn call_tool(&self, params: CallToolParams) -> anyhow::Result<CallToolResult>;
}

#[derive(Debug, Clone)]
pub struct McpServerConfig {
    pub server_info: McpServerInfo,
    pub instructions: Option<String>,
    pub capabilities: Value,
    pub supported_protocol_versions: Vec<String>,
}

impl McpServerConfig {
    pub fn default_for_binary(name: &str, version: &str) -> Self {
        Self {
            server_info: McpServerInfo {
                name: name.to_string(),
                version: version.to_string(),
            },
            instructions: None,
            capabilities: serde_json::json!({
                "tools": {
                    "listChanged": false
                }
            }),
            supported_protocol_versions: vec![
                PROTOCOL_VERSION_LATEST.to_string(),
                PROTOCOL_VERSION_2025_06_18.to_string(),
            ],
        }
    }

    fn negotiate_protocol(&self, requested: &str) -> String {
        if self
            .supported_protocol_versions
            .iter()
            .any(|v| v == requested)
        {
            requested.to_string()
        } else {
            PROTOCOL_VERSION_LATEST.to_string()
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ConnState {
    New,
    InitResponded,
    Ready,
}

/// MCP server connection state machine (lifecycle enforcement + method routing).
pub struct McpConnection {
    cfg: McpServerConfig,
    handler: Arc<dyn McpHandler>,
    state: ConnState,
    protocol_version: Option<String>,
}

impl McpConnection {
    pub fn new(cfg: McpServerConfig, handler: Arc<dyn McpHandler>) -> Self {
        Self {
            cfg,
            handler,
            state: ConnState::New,
            protocol_version: None,
        }
    }

    pub fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    /// Handle a single JSON-RPC message.
    ///
    /// Returns `Some(response)` for requests, `None` for notifications or ignored messages.
    pub async fn handle_message(&mut self, msg: JsonRpcMessage) -> Option<JsonRpcResponse> {
        match msg {
            JsonRpcMessage::Request(req) => Some(self.handle_request(req).await),
            JsonRpcMessage::Notification(n) => {
                self.handle_notification(n).await;
                None
            }
            JsonRpcMessage::Response(_) => None,
        }
    }

    fn invalid_request(id: JsonRpcId, message: impl Into<String>) -> JsonRpcResponse {
        JsonRpcResponse::err(
            id,
            JsonRpcError {
                code: -32600,
                message: message.into(),
                data: None,
            },
        )
    }

    fn method_not_found(id: JsonRpcId) -> JsonRpcResponse {
        JsonRpcResponse::err(
            id,
            JsonRpcError {
                code: -32601,
                message: "method not found".to_string(),
                data: None,
            },
        )
    }

    fn invalid_params(id: JsonRpcId, detail: String) -> JsonRpcResponse {
        JsonRpcResponse::err(
            id,
            JsonRpcError {
                code: -32602,
                message: "invalid params".to_string(),
                data: Some(serde_json::json!({ "detail": detail })),
            },
        )
    }

    fn internal_error(id: JsonRpcId, detail: String) -> JsonRpcResponse {
        JsonRpcResponse::err(
            id,
            JsonRpcError {
                code: -32603,
                message: "internal error".to_string(),
                data: Some(serde_json::json!({ "detail": detail })),
            },
        )
    }

    fn not_initialized(id: JsonRpcId) -> JsonRpcResponse {
        JsonRpcResponse::err(
            id,
            JsonRpcError {
                code: -32002,
                message: "not initialized".to_string(),
                data: None,
            },
        )
    }

    async fn handle_request(&mut self, req: JsonRpcRequest) -> JsonRpcResponse {
        if req.jsonrpc != "2.0" {
            return Self::invalid_request(req.id, "invalid jsonrpc version");
        }

        match req.method.as_str() {
            "initialize" => self.handle_initialize(req).await,
            "ping" => {
                // Allow ping in any state.
                JsonRpcResponse::ok(req.id, serde_json::json!({}))
            }
            "tools/list" => {
                if self.state != ConnState::Ready {
                    return Self::not_initialized(req.id);
                }
                let params = match req.params {
                    Some(v) => {
                        serde_json::from_value::<ListToolsParams>(v).map_err(|e| e.to_string())
                    }
                    None => Ok(ListToolsParams::default()),
                };
                let params = match params {
                    Ok(p) => p,
                    Err(e) => return Self::invalid_params(req.id, e),
                };

                match self.handler.list_tools(params).await {
                    Ok(res) => JsonRpcResponse::ok(
                        req.id,
                        serde_json::to_value(res).unwrap_or(Value::Null),
                    ),
                    Err(e) => Self::internal_error(req.id, e.to_string()),
                }
            }
            "tools/call" => {
                if self.state != ConnState::Ready {
                    return Self::not_initialized(req.id);
                }
                let Some(v) = req.params else {
                    return Self::invalid_params(req.id, "missing params".to_string());
                };
                let params = match serde_json::from_value::<CallToolParams>(v) {
                    Ok(p) => p,
                    Err(e) => return Self::invalid_params(req.id, e.to_string()),
                };

                match self.handler.call_tool(params).await {
                    Ok(res) => JsonRpcResponse::ok(
                        req.id,
                        serde_json::to_value(res).unwrap_or(Value::Null),
                    ),
                    Err(e) => Self::internal_error(req.id, e.to_string()),
                }
            }
            _ => Self::method_not_found(req.id),
        }
    }

    async fn handle_initialize(&mut self, req: JsonRpcRequest) -> JsonRpcResponse {
        if self.state != ConnState::New {
            return Self::invalid_request(req.id, "already initialized");
        }

        let Some(params) = req.params else {
            return Self::invalid_params(req.id, "missing params".to_string());
        };

        let init: InitializeParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => return Self::invalid_params(req.id, e.to_string()),
        };

        let negotiated = self.cfg.negotiate_protocol(&init.protocol_version);
        self.protocol_version = Some(negotiated.clone());
        self.state = ConnState::InitResponded;

        let result = InitializeResult {
            protocol_version: negotiated,
            capabilities: self.cfg.capabilities.clone(),
            server_info: self.cfg.server_info.clone(),
            instructions: self.cfg.instructions.clone(),
        };

        JsonRpcResponse::ok(req.id, serde_json::to_value(result).unwrap_or(Value::Null))
    }

    async fn handle_notification(&mut self, n: JsonRpcNotification) {
        if n.jsonrpc != "2.0" {
            return;
        }

        if n.method.as_str() == "notifications/initialized"
            && self.state == ConnState::InitResponded
        {
            self.state = ConnState::Ready;
        }
    }

    pub fn make_initialized_notification() -> JsonRpcNotification {
        JsonRpcNotification::new("notifications/initialized", None)
    }

    /// Create a JSON-RPC request for `initialize`.
    pub fn make_initialize_request(id: JsonRpcId, params: InitializeParams) -> JsonRpcRequest {
        JsonRpcRequest::new(
            id,
            "initialize",
            Some(serde_json::to_value(params).unwrap()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContentBlock, Tool};

    struct DummyHandler;

    #[async_trait]
    impl McpHandler for DummyHandler {
        async fn list_tools(&self, _params: ListToolsParams) -> anyhow::Result<ListToolsResult> {
            Ok(ListToolsResult {
                tools: vec![Tool {
                    name: "echo".to_string(),
                    title: Some("Echo".to_string()),
                    description: Some("demo".to_string()),
                    input_schema: serde_json::json!({"type":"object"}),
                }],
                next_cursor: None,
            })
        }

        async fn call_tool(&self, params: CallToolParams) -> anyhow::Result<CallToolResult> {
            Ok(CallToolResult {
                content: vec![ContentBlock::Text {
                    text: format!("called {}", params.name),
                }],
                structured_content: params.arguments,
                is_error: Some(false),
                meta: None,
            })
        }
    }

    fn mk_conn() -> McpConnection {
        let cfg = McpServerConfig::default_for_binary("test", "0.0.0");
        let h: Arc<dyn McpHandler> = Arc::new(DummyHandler);
        McpConnection::new(cfg, h)
    }

    #[tokio::test]
    async fn lifecycle_requires_initialize_and_initialized_notification() {
        let mut conn = mk_conn();

        // tools/list before initialize -> not initialized
        let req = JsonRpcRequest::new(
            JsonRpcId::Number(1),
            "tools/list",
            Some(serde_json::json!({})),
        );
        let resp = conn
            .handle_message(JsonRpcMessage::Request(req))
            .await
            .expect("response");
        assert_eq!(resp.error.as_ref().map(|e| e.code), Some(-32002));

        // ping allowed before initialize
        let ping = JsonRpcRequest::new(JsonRpcId::Number(2), "ping", None);
        let resp = conn
            .handle_message(JsonRpcMessage::Request(ping))
            .await
            .expect("response");
        assert!(resp.error.is_none());

        // initialize
        let init_params = InitializeParams::new_default("client", "0.0.0");
        let init_req = JsonRpcRequest::new(
            JsonRpcId::Number(3),
            "initialize",
            Some(serde_json::to_value(init_params).unwrap()),
        );
        let resp = conn
            .handle_message(JsonRpcMessage::Request(init_req))
            .await
            .expect("response");
        assert!(resp.error.is_none());

        // tools/list still blocked until notifications/initialized
        let req = JsonRpcRequest::new(
            JsonRpcId::Number(4),
            "tools/list",
            Some(serde_json::json!({})),
        );
        let resp = conn
            .handle_message(JsonRpcMessage::Request(req))
            .await
            .expect("response");
        assert_eq!(resp.error.as_ref().map(|e| e.code), Some(-32002));

        // initialized notification
        conn.handle_message(JsonRpcMessage::Notification(
            McpConnection::make_initialized_notification(),
        ))
        .await;

        // tools/list now works
        let req = JsonRpcRequest::new(
            JsonRpcId::Number(5),
            "tools/list",
            Some(serde_json::json!({})),
        );
        let resp = conn
            .handle_message(JsonRpcMessage::Request(req))
            .await
            .expect("response");
        assert!(resp.error.is_none());
        assert!(resp.result.is_some());
    }

    #[tokio::test]
    async fn unknown_method_is_error() {
        let mut conn = mk_conn();
        let req = JsonRpcRequest::new(JsonRpcId::Number(1), "nope", None);
        let resp = conn
            .handle_message(JsonRpcMessage::Request(req))
            .await
            .expect("response");
        assert_eq!(resp.error.as_ref().map(|e| e.code), Some(-32601));
    }
}
