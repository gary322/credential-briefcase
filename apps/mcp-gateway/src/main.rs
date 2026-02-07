use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use briefcase_api::types::{CallToolRequest, CallToolResponse};
use briefcase_api::{BriefcaseClient, DaemonEndpoint};
use briefcase_core::{ToolCall, ToolCallContext};
use briefcase_mcp::{
    CallToolParams, CallToolResult, ContentBlock, JsonRpcError, JsonRpcId, JsonRpcMessage,
    JsonRpcRequest, JsonRpcResponse, ListToolsParams, ListToolsResult, McpConnection, McpHandler,
    McpServerConfig, Tool,
};
use clap::Parser;
use directories::ProjectDirs;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;
use tracing::{Instrument as _, info};
use uuid::Uuid;

use briefcase_otel::TracingInitOptions;

#[derive(Debug, Parser)]
#[command(
    name = "briefcase-mcp-gateway",
    version,
    about = "Single MCP surface for tools"
)]
struct Args {
    /// Directory for runtime state (auth token, socket).
    #[arg(long, env = "BRIEFCASE_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Use a TCP daemon endpoint, e.g. `http://127.0.0.1:3000`.
    #[arg(long, env = "BRIEFCASE_DAEMON_BASE_URL")]
    daemon_base_url: Option<String>,

    /// Override the unix socket path (Unix only).
    #[arg(long, env = "BRIEFCASE_DAEMON_UNIX_SOCKET")]
    unix_socket: Option<PathBuf>,

    /// Override the daemon auth token (otherwise read from <data_dir>/auth_token).
    #[arg(long, env = "BRIEFCASE_AUTH_TOKEN")]
    auth_token: Option<String>,

    /// Listen on HTTP using MCP Streamable HTTP transport.
    #[arg(long, env = "BRIEFCASE_MCP_HTTP_ADDR")]
    http_addr: Option<SocketAddr>,

    /// HTTP path for MCP Streamable HTTP endpoint.
    #[arg(long, env = "BRIEFCASE_MCP_HTTP_PATH", default_value = "/mcp")]
    http_path: String,

    /// Disable stdio transport (use HTTP only).
    #[arg(long, env = "BRIEFCASE_MCP_NO_STDIO", default_value_t = false)]
    no_stdio: bool,
}

struct GatewayHandler {
    client: BriefcaseClient,
}

#[async_trait::async_trait]
impl McpHandler for GatewayHandler {
    async fn list_tools(&self, _params: ListToolsParams) -> anyhow::Result<ListToolsResult> {
        let client = self.client.clone();
        async move {
            let list = client.list_tools().await?;
            let tools = list
                .tools
                .into_iter()
                .map(|t| Tool {
                    name: t.id,
                    title: Some(t.name),
                    description: Some(t.description),
                    input_schema: t.input_schema,
                })
                .collect::<Vec<_>>();
            Ok(ListToolsResult {
                tools,
                next_cursor: None,
            })
        }
        .instrument(tracing::info_span!("gateway.list_tools"))
        .await
    }

    async fn call_tool(&self, params: CallToolParams) -> anyhow::Result<CallToolResult> {
        let client = self.client.clone();
        let tool_id = params.name.clone();
        let tool_id_for_span = tool_id.clone();
        async move {
            let args = params.arguments.unwrap_or_else(|| serde_json::json!({}));
            let call = ToolCall {
                tool_id: tool_id.clone(),
                args,
                context: ToolCallContext::new(),
                approval_token: None,
            };

            let resp = client.call_tool(CallToolRequest { call }).await?;
            Ok(match resp {
                CallToolResponse::Ok { result } => {
                    let pretty = serde_json::to_string_pretty(&result.content)
                        .unwrap_or_else(|_| result.content.to_string());
                    CallToolResult {
                        content: vec![ContentBlock::Text { text: pretty }],
                        structured_content: Some(result.content),
                        is_error: Some(false),
                        meta: Some(serde_json::json!({ "provenance": result.provenance })),
                    }
                }
                CallToolResponse::ApprovalRequired { approval } => CallToolResult {
                    content: vec![ContentBlock::Text {
                        text: format!(
                            "Approval required for tool `{}`: {}. Approval ID: {}. Approve via `briefcase approvals approve {}`.",
                            approval.tool_id, approval.reason, approval.id, approval.id
                        ),
                    }],
                    structured_content: None,
                    is_error: Some(true),
                    meta: Some(serde_json::json!({ "approval": approval })),
                },
                CallToolResponse::Denied { reason } => CallToolResult {
                    content: vec![ContentBlock::Text {
                        text: format!("Denied: {reason}"),
                    }],
                    structured_content: None,
                    is_error: Some(true),
                    meta: None,
                },
                CallToolResponse::Error { message } => CallToolResult {
                    content: vec![ContentBlock::Text {
                        text: format!("Error: {message}"),
                    }],
                    structured_content: None,
                    is_error: Some(true),
                    meta: None,
                },
            })
        }
        .instrument(tracing::info_span!(
            "gateway.call_tool",
            tool_id = %tool_id_for_span
        ))
        .await
    }
}

#[derive(Clone)]
struct HttpState {
    cfg: McpServerConfig,
    handler: Arc<dyn McpHandler>,
    sessions: Arc<Mutex<HashMap<String, McpConnection>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    briefcase_otel::init_tracing(TracingInitOptions {
        service_name: "mcp-gateway",
        service_version: env!("CARGO_PKG_VERSION"),
        default_env_filter: "info",
    })?;

    let args = Args::parse();
    let data_dir = resolve_data_dir(args.data_dir.as_deref())?;

    let auth_token = match args.auth_token {
        Some(t) => t,
        None => std::fs::read_to_string(data_dir.join("auth_token"))
            .context("read daemon auth_token")?
            .trim()
            .to_string(),
    };

    let endpoint = match args.daemon_base_url {
        Some(base_url) => DaemonEndpoint::Tcp { base_url },
        None => {
            #[cfg(unix)]
            {
                let socket_path = args
                    .unix_socket
                    .unwrap_or_else(|| data_dir.join("briefcased.sock"));
                DaemonEndpoint::Unix { socket_path }
            }
            #[cfg(not(unix))]
            {
                anyhow::bail!("unix sockets not supported; set --daemon-base-url");
            }
        }
    };

    let client = BriefcaseClient::new(endpoint, auth_token);
    client.health().await.context("connect to daemon")?;
    info!("connected to briefcased");

    let handler: Arc<dyn McpHandler> = Arc::new(GatewayHandler { client });
    let cfg =
        McpServerConfig::default_for_binary("briefcase-mcp-gateway", env!("CARGO_PKG_VERSION"));

    let http_task = if let Some(addr) = args.http_addr {
        let st = HttpState {
            cfg: cfg.clone(),
            handler: handler.clone(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        };
        let path = args.http_path.clone();
        Some(tokio::spawn(
            async move { serve_http(addr, path, st).await },
        ))
    } else {
        None
    };

    if !args.no_stdio {
        run_stdio(cfg, handler).await?;
    }

    if let Some(t) = http_task {
        t.await.context("http task join")??;
    }

    Ok(())
}

async fn run_stdio(cfg: McpServerConfig, handler: Arc<dyn McpHandler>) -> anyhow::Result<()> {
    let mut conn = McpConnection::new(cfg, handler);

    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let val: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let resp = JsonRpcResponse::err(
                    JsonRpcId::Null,
                    JsonRpcError {
                        code: -32700,
                        message: "parse error".to_string(),
                        data: Some(serde_json::json!({ "detail": e.to_string() })),
                    },
                );
                write_jsonrpc(&mut stdout, &resp).await?;
                continue;
            }
        };

        if val.is_array() {
            let resp = JsonRpcResponse::err(
                JsonRpcId::Null,
                JsonRpcError {
                    code: -32600,
                    message: "batching not supported".to_string(),
                    data: None,
                },
            );
            write_jsonrpc(&mut stdout, &resp).await?;
            continue;
        }

        let msg: JsonRpcMessage = match serde_json::from_value(val) {
            Ok(m) => m,
            Err(e) => {
                let resp = JsonRpcResponse::err(
                    JsonRpcId::Null,
                    JsonRpcError {
                        code: -32600,
                        message: "invalid request".to_string(),
                        data: Some(serde_json::json!({ "detail": e.to_string() })),
                    },
                );
                write_jsonrpc(&mut stdout, &resp).await?;
                continue;
            }
        };

        if let Some(resp) = conn.handle_message(msg).await {
            write_jsonrpc(&mut stdout, &resp).await?;
        }
    }

    Ok(())
}

async fn write_jsonrpc(
    stdout: &mut tokio::io::Stdout,
    resp: &JsonRpcResponse,
) -> anyhow::Result<()> {
    let out = serde_json::to_string(resp)?;
    stdout.write_all(out.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}

async fn serve_http(addr: SocketAddr, path: String, st: HttpState) -> anyhow::Result<()> {
    let app = Router::new()
        .route(&path, post(http_post).delete(http_delete).get(http_get))
        .layer(TraceLayer::new_for_http())
        .with_state(st);

    info!(addr = %addr, path = %path, "starting MCP HTTP server");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn http_get() -> impl IntoResponse {
    // Optional SSE stream is not implemented for this gateway (no server-initiated messages).
    (StatusCode::METHOD_NOT_ALLOWED, "sse not supported")
}

async fn http_delete(State(st): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(sid) = header_str(&headers, "mcp-session-id") else {
        return (StatusCode::BAD_REQUEST, "missing mcp-session-id").into_response();
    };
    st.sessions.lock().await.remove(sid);
    StatusCode::ACCEPTED.into_response()
}

async fn http_post(State(st): State<HttpState>, headers: HeaderMap, body: String) -> Response {
    if let Err((code, msg)) = validate_origin(&headers) {
        return (code, msg).into_response();
    }

    // Reject unsupported protocol version header values (spec requires 400).
    if let Some(v) = header_str(&headers, "mcp-protocol-version")
        && v.trim().is_empty()
    {
        return (StatusCode::BAD_REQUEST, "invalid mcp-protocol-version").into_response();
    }

    let val: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            let resp = JsonRpcResponse::err(
                JsonRpcId::Null,
                JsonRpcError {
                    code: -32700,
                    message: "parse error".to_string(),
                    data: Some(serde_json::json!({ "detail": e.to_string() })),
                },
            );
            return jsonrpc_http_response(resp, None);
        }
    };

    if val.is_array() {
        let resp = JsonRpcResponse::err(
            JsonRpcId::Null,
            JsonRpcError {
                code: -32600,
                message: "batching not supported".to_string(),
                data: None,
            },
        );
        return jsonrpc_http_response(resp, None);
    }

    let msg: JsonRpcMessage = match serde_json::from_value(val) {
        Ok(m) => m,
        Err(e) => {
            let resp = JsonRpcResponse::err(
                JsonRpcId::Null,
                JsonRpcError {
                    code: -32600,
                    message: "invalid request".to_string(),
                    data: Some(serde_json::json!({ "detail": e.to_string() })),
                },
            );
            return jsonrpc_http_response(resp, None);
        }
    };

    // Initialize starts a new session.
    if let JsonRpcMessage::Request(JsonRpcRequest { method, .. }) = &msg
        && method == "initialize"
    {
        let sid = Uuid::new_v4().to_string();
        let mut conn = McpConnection::new(st.cfg.clone(), st.handler.clone());
        let resp = conn.handle_message(msg).await;
        st.sessions.lock().await.insert(sid.clone(), conn);
        return match resp {
            Some(r) => jsonrpc_http_response(r, Some(&sid)),
            None => StatusCode::ACCEPTED.into_response(),
        };
    }

    // Other messages require a session.
    let Some(sid) = header_str(&headers, "mcp-session-id") else {
        return (StatusCode::BAD_REQUEST, "missing mcp-session-id").into_response();
    };

    let mut sessions = st.sessions.lock().await;
    let Some(conn) = sessions.get_mut(sid) else {
        return (StatusCode::NOT_FOUND, "unknown mcp-session-id").into_response();
    };

    match msg {
        JsonRpcMessage::Notification(_) => {
            conn.handle_message(msg).await;
            StatusCode::ACCEPTED.into_response()
        }
        _ => match conn.handle_message(msg).await {
            Some(r) => jsonrpc_http_response(r, Some(sid)),
            None => StatusCode::ACCEPTED.into_response(),
        },
    }
}

fn validate_origin(headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let Some(origin) = headers
        .get("origin")
        .and_then(|h| h.to_str().ok())
        .filter(|s| !s.trim().is_empty())
    else {
        return Ok(());
    };

    let u = url::Url::parse(origin).map_err(|_| (StatusCode::FORBIDDEN, "invalid origin"))?;
    let host = u.host().ok_or((StatusCode::FORBIDDEN, "invalid origin"))?;
    let is_loopback = match host {
        url::Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    };
    if !is_loopback {
        return Err((StatusCode::FORBIDDEN, "origin not allowed"));
    }

    Ok(())
}

fn jsonrpc_http_response(resp: JsonRpcResponse, session_id: Option<&str>) -> Response {
    let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json");

    if let Some(sid) = session_id
        && let Ok(v) = HeaderValue::from_str(sid)
    {
        builder = builder.header("mcp-session-id", v);
    }

    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|h| h.to_str().ok())
}

fn resolve_data_dir(cli: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(p) = cli {
        return Ok(p.to_path_buf());
    }

    let proj = ProjectDirs::from("com", "briefcase", "credential-briefcase")
        .context("resolve platform data dir")?;
    Ok(proj.data_local_dir().to_path_buf())
}
