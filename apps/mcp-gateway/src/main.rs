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
use briefcase_core::{COMPATIBILITY_PROFILE_VERSION, ProfileMode, ToolCall, ToolCallContext};
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
use tracing::{Instrument as _, info, warn};
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

    /// Override the Windows named pipe path (Windows only), e.g. `\\\\.\\pipe\\briefcased-...`.
    #[cfg(windows)]
    #[arg(long, env = "BRIEFCASE_DAEMON_NAMED_PIPE")]
    named_pipe: Option<String>,

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

    /// Profile mode for compatibility metadata.
    #[arg(long, env = "BRIEFCASE_PROFILE_MODE", default_value = "reference")]
    profile_mode: String,
}

struct GatewayHandler {
    client: BriefcaseClient,
    profile_mode: ProfileMode,
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
        let profile_mode = self.profile_mode;
        let tool_id = params.name.clone();
        let tool_id_for_span = tool_id.clone();
        async move {
            let args = params.arguments.unwrap_or_else(|| serde_json::json!({}));
            let call = ToolCall {
                tool_id: tool_id.clone(),
                args,
                context: ToolCallContext::new(),
                approval_token: params.approval_token,
            };

            let resp = client.call_tool(CallToolRequest { call }).await?;
            let compat_meta = serde_json::json!({
                "mode": profile_mode,
                "compatibility_profile": COMPATIBILITY_PROFILE_VERSION
            });
            Ok(match resp {
                CallToolResponse::Ok { result } => {
                    let pretty = serde_json::to_string_pretty(&result.content)
                        .unwrap_or_else(|_| result.content.to_string());
                    CallToolResult {
                        content: vec![ContentBlock::Text { text: pretty }],
                        structured_content: Some(result.content),
                        is_error: Some(false),
                        meta: Some(serde_json::json!({
                            "provenance": result.provenance,
                            "compatibility": compat_meta
                        })),
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
                    meta: Some(serde_json::json!({
                        "approval": approval,
                        "compatibility": compat_meta
                    })),
                },
                CallToolResponse::Denied { reason } => CallToolResult {
                    content: vec![ContentBlock::Text {
                        text: format!("Denied: {reason}"),
                    }],
                    structured_content: None,
                    is_error: Some(true),
                    meta: Some(serde_json::json!({ "compatibility": compat_meta })),
                },
                CallToolResponse::Error { message } => CallToolResult {
                    content: vec![ContentBlock::Text {
                        text: format!("Error: {message}"),
                    }],
                    structured_content: None,
                    is_error: Some(true),
                    meta: Some(serde_json::json!({ "compatibility": compat_meta })),
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
    let profile_mode = args
        .profile_mode
        .parse::<ProfileMode>()
        .map_err(|e| anyhow::anyhow!("invalid BRIEFCASE_PROFILE_MODE: {e}"))?;

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
            #[cfg(windows)]
            {
                let pipe_name = args
                    .named_pipe
                    .unwrap_or_else(|| briefcase_api::default_named_pipe_name(&auth_token));
                DaemonEndpoint::NamedPipe { pipe_name }
            }
            #[cfg(all(not(unix), not(windows)))]
            {
                anyhow::bail!("no default IPC transport on this platform; set --daemon-base-url");
            }
        }
    };

    let client = BriefcaseClient::new(endpoint, auth_token);
    client.health().await.context("connect to daemon")?;
    if let Ok(id) = client.identity().await
        && let Some(daemon_mode) = id.profile_mode
        && daemon_mode != profile_mode
    {
        warn!(
            daemon_mode = daemon_mode.as_str(),
            gateway_mode = profile_mode.as_str(),
            "gateway/daemon profile mode mismatch"
        );
    }
    info!("connected to briefcased");

    let handler: Arc<dyn McpHandler> = Arc::new(GatewayHandler {
        client,
        profile_mode,
    });
    let mut cfg =
        McpServerConfig::default_for_binary("briefcase-mcp-gateway", env!("CARGO_PKG_VERSION"));
    cfg.capabilities = serde_json::json!({
        "tools": { "listChanged": false },
        "briefcase": {
            "compatibility_profile": COMPATIBILITY_PROFILE_VERSION,
            "mode": profile_mode,
        }
    });

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

#[cfg(test)]
mod tests {
    use super::*;

    use axum::extract::{Form, Query, State};
    use axum::http::HeaderMap;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use chrono::Utc;
    use tempfile::tempdir;

    async fn start_test_daemon() -> anyhow::Result<(
        tempfile::TempDir,
        tokio::task::JoinHandle<()>,
        BriefcaseClient,
    )> {
        let dir = tempdir().context("tempdir")?;
        let db_path = dir.path().join("briefcase.sqlite");
        let auth_token = Uuid::new_v4().to_string();
        let secrets: Arc<dyn briefcase_secrets::SecretStore> =
            Arc::new(briefcase_secrets::InMemorySecretStore::default());

        let state = briefcased::app::AppState::init_with_options(
            &db_path,
            auth_token.clone(),
            // Tool tests here do not exercise provider traffic.
            "http://127.0.0.1:9099".to_string(),
            secrets,
            briefcased::app::AppOptions::default(),
        )
        .await
        .context("init daemon state")?;

        let app = briefcased::app::router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind daemon")?;
        let addr = listener.local_addr().context("daemon local_addr")?;
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let client = BriefcaseClient::new(
            DaemonEndpoint::Tcp {
                base_url: format!("http://{addr}"),
            },
            auth_token,
        );

        Ok((dir, task, client))
    }

    #[derive(Clone)]
    struct MockOAuthProviderState {
        refresh_token: Arc<Mutex<String>>,
        access_token: Arc<Mutex<String>>,
        capability_token: Arc<Mutex<String>>,
    }

    async fn start_mock_oauth_provider() -> anyhow::Result<(
        SocketAddr,
        MockOAuthProviderState,
        tokio::task::JoinHandle<()>,
    )> {
        #[derive(Debug, serde::Deserialize)]
        struct OAuthTokenForm {
            grant_type: String,
            refresh_token: Option<String>,
            // Authorization code grant fields (ignored in this mock beyond presence).
            code: Option<String>,
            redirect_uri: Option<String>,
            client_id: Option<String>,
            code_verifier: Option<String>,
        }

        async fn oauth_token(
            State(st): State<MockOAuthProviderState>,
            Form(body): Form<OAuthTokenForm>,
        ) -> (StatusCode, Json<serde_json::Value>) {
            match body.grant_type.as_str() {
                "authorization_code" => {
                    if body.code.is_none()
                        || body.redirect_uri.is_none()
                        || body.client_id.is_none()
                        || body.code_verifier.is_none()
                    {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error":"invalid_request"})),
                        );
                    }
                    let at = Uuid::new_v4().to_string();
                    *st.access_token.lock().await = at.clone();
                    let rt = st.refresh_token.lock().await.clone();
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "access_token": at,
                            "refresh_token": rt,
                            "token_type": "Bearer",
                            "expires_in": 600
                        })),
                    )
                }
                "refresh_token" => {
                    let want = st.refresh_token.lock().await.clone();
                    if body.refresh_token.as_deref() != Some(&want) {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error":"invalid_grant"})),
                        );
                    }
                    let at = Uuid::new_v4().to_string();
                    *st.access_token.lock().await = at.clone();
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "access_token": at,
                            "token_type": "Bearer",
                            "expires_in": 600
                        })),
                    )
                }
                _ => (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error":"unsupported_grant"})),
                ),
            }
        }

        async fn token(
            State(st): State<MockOAuthProviderState>,
            headers: HeaderMap,
        ) -> (StatusCode, Json<serde_json::Value>) {
            let want = format!("Bearer {}", st.access_token.lock().await.clone());
            let got = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default()
                .to_string();
            if got != want {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error":"unauthorized"})),
                );
            }

            let cap = st.capability_token.lock().await.clone();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "token": cap,
                    "expires_at_rfc3339": (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
                    "max_calls": 50
                })),
            )
        }

        async fn quote(
            State(st): State<MockOAuthProviderState>,
            headers: HeaderMap,
            Query(params): Query<std::collections::HashMap<String, String>>,
        ) -> (StatusCode, Json<serde_json::Value>) {
            let symbol = params.get("symbol").cloned().unwrap_or_default();
            if symbol.is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error":"missing_symbol"})),
                );
            }

            let cap = st.capability_token.lock().await.clone();
            let want_bearer = format!("Bearer {cap}");
            let want_dpop = format!("DPoP {cap}");
            let got = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let ok = got == want_bearer
                || (got == want_dpop
                    && headers
                        .get("dpop")
                        .and_then(|h| h.to_str().ok())
                        .map(|v| !v.trim().is_empty())
                        .unwrap_or(false));
            if !ok {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error":"unauthorized"})),
                );
            }

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "symbol": symbol,
                    "price": 123.45,
                    "ts": Utc::now().to_rfc3339(),
                })),
            )
        }

        let st = MockOAuthProviderState {
            refresh_token: Arc::new(Mutex::new(Uuid::new_v4().to_string())),
            access_token: Arc::new(Mutex::new(Uuid::new_v4().to_string())),
            capability_token: Arc::new(Mutex::new(Uuid::new_v4().to_string())),
        };

        let app = Router::new()
            .route("/oauth/token", post(oauth_token))
            .route("/token", post(token))
            .route("/api/quote", get(quote))
            .with_state(st.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Ok((addr, st, handle))
    }

    #[tokio::test]
    async fn approval_interop_mcp_approval_token_roundtrip() -> anyhow::Result<()> {
        let (_dir, daemon_task, client) = start_test_daemon().await?;

        let handler: Arc<dyn McpHandler> = Arc::new(GatewayHandler {
            client: client.clone(),
            profile_mode: ProfileMode::Reference,
        });
        let cfg = McpServerConfig::default_for_binary("test-mcp-gateway", "0.0.0");
        let mut conn = McpConnection::new(cfg, handler);

        // MCP lifecycle handshake.
        let init_params = briefcase_mcp::InitializeParams::new_default("test-client", "0.0.0");
        let init = JsonRpcMessage::Request(JsonRpcRequest::new(
            JsonRpcId::Number(1),
            "initialize",
            Some(serde_json::to_value(init_params)?),
        ));
        let init_resp = conn
            .handle_message(init)
            .await
            .context("missing init response")?;
        assert!(
            init_resp.error.is_none(),
            "init_resp={}",
            serde_json::to_string(&init_resp).unwrap_or_default()
        );

        let _ = conn
            .handle_message(JsonRpcMessage::Notification(
                McpConnection::make_initialized_notification(),
            ))
            .await;

        // note_add requires approval.
        let call1 = JsonRpcMessage::Request(JsonRpcRequest::new(
            JsonRpcId::Number(2),
            "tools/call",
            Some(serde_json::to_value(CallToolParams {
                name: "note_add".to_string(),
                arguments: Some(serde_json::json!({ "text": "hello" })),
                approval_token: None,
            })?),
        ));
        let resp1 = conn
            .handle_message(call1)
            .await
            .context("missing call response")?;
        assert!(resp1.error.is_none(), "resp1 error={:?}", resp1.error);
        let r1: CallToolResult = serde_json::from_value(resp1.result.context("missing result")?)
            .context("decode CallToolResult")?;
        assert_eq!(r1.is_error, Some(true));
        let meta1 = r1.meta.context("missing _meta")?;
        let approval_id = meta1
            .get("approval")
            .and_then(|a| a.get("id"))
            .and_then(|v| v.as_str())
            .context("missing approval.id")?;
        let approval_id = Uuid::parse_str(approval_id).context("parse approval id")?;

        let approved = client.approve(&approval_id).await?;

        // Retry with approvalToken.
        let call2 = JsonRpcMessage::Request(JsonRpcRequest::new(
            JsonRpcId::Number(3),
            "tools/call",
            Some(serde_json::to_value(CallToolParams {
                name: "note_add".to_string(),
                arguments: Some(serde_json::json!({ "text": "hello" })),
                approval_token: Some(approved.approval_token),
            })?),
        ));
        let resp2 = conn
            .handle_message(call2)
            .await
            .context("missing call response")?;
        assert!(resp2.error.is_none(), "resp2 error={:?}", resp2.error);

        let r2: CallToolResult = serde_json::from_value(resp2.result.context("missing result")?)
            .context("decode CallToolResult")?;
        assert_eq!(r2.is_error, Some(false));
        assert!(
            r2.structured_content
                .as_ref()
                .and_then(|v| v.get("note_id"))
                .is_some(),
            "expected structured_content.note_id"
        );

        let meta2 = r2.meta.context("missing _meta")?;
        assert!(
            meta2.get("compatibility").is_some(),
            "expected _meta.compatibility"
        );
        assert!(
            meta2.get("provenance").is_some(),
            "expected _meta.provenance"
        );

        daemon_task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn e2e_profile_smoke_agent_gateway_daemon_provider() -> anyhow::Result<()> {
        let (provider_addr, _provider_state, provider_task) = start_mock_oauth_provider().await?;
        let provider_base_url = format!("http://{provider_addr}");

        // Start daemon pointing at our mock provider.
        let dir = tempdir()?;
        let db_path = dir.path().join("briefcase.sqlite");
        let auth_token = Uuid::new_v4().to_string();
        let secrets: Arc<dyn briefcase_secrets::SecretStore> =
            Arc::new(briefcase_secrets::InMemorySecretStore::default());

        let state = briefcased::app::AppState::init_with_options(
            &db_path,
            auth_token.clone(),
            provider_base_url,
            secrets,
            briefcased::app::AppOptions {
                profile_mode: ProfileMode::Staging,
                ..briefcased::app::AppOptions::default()
            },
        )
        .await?;

        let daemon_app = briefcased::app::router(state);
        let daemon_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let daemon_addr = daemon_listener.local_addr()?;
        let daemon_task = tokio::spawn(async move {
            let _ = axum::serve(daemon_listener, daemon_app).await;
        });

        let client = BriefcaseClient::new(
            DaemonEndpoint::Tcp {
                base_url: format!("http://{daemon_addr}"),
            },
            auth_token,
        );

        // Simulate admin OAuth enrollment (refresh token remains daemon-side only).
        client
            .oauth_exchange(
                "demo",
                briefcase_api::types::OAuthExchangeRequest {
                    code: "code".to_string(),
                    redirect_uri: "http://127.0.0.1/callback".to_string(),
                    client_id: "briefcase-cli".to_string(),
                    code_verifier: "verifier".to_string(),
                },
            )
            .await?;

        // Agent call via MCP gateway.
        let handler: Arc<dyn McpHandler> = Arc::new(GatewayHandler {
            client: client.clone(),
            profile_mode: ProfileMode::Staging,
        });
        let cfg = McpServerConfig::default_for_binary("test-mcp-gateway", "0.0.0");
        let mut conn = McpConnection::new(cfg, handler);

        // MCP lifecycle handshake.
        let init_params = briefcase_mcp::InitializeParams::new_default("test-client", "0.0.0");
        let init = JsonRpcMessage::Request(JsonRpcRequest::new(
            JsonRpcId::Number(1),
            "initialize",
            Some(serde_json::to_value(init_params)?),
        ));
        let init_resp = conn
            .handle_message(init)
            .await
            .context("missing init response")?;
        assert!(
            init_resp.error.is_none(),
            "init_resp error={:?}",
            init_resp.error
        );
        let _ = conn
            .handle_message(JsonRpcMessage::Notification(
                McpConnection::make_initialized_notification(),
            ))
            .await;

        // Quote should succeed end-to-end (gateway -> daemon -> provider).
        let quote_call = JsonRpcMessage::Request(JsonRpcRequest::new(
            JsonRpcId::Number(2),
            "tools/call",
            Some(serde_json::to_value(CallToolParams {
                name: "quote".to_string(),
                arguments: Some(serde_json::json!({ "symbol": "TEST" })),
                approval_token: None,
            })?),
        ));
        let quote_resp = conn
            .handle_message(quote_call)
            .await
            .context("missing quote response")?;
        assert!(
            quote_resp.error.is_none(),
            "quote_resp error={:?}",
            quote_resp.error
        );
        let out: CallToolResult =
            serde_json::from_value(quote_resp.result.context("missing result")?)?;
        assert_eq!(
            out.is_error,
            Some(false),
            "quote call failed: {}",
            serde_json::to_string(&out).unwrap_or_default()
        );
        let symbol = out
            .structured_content
            .as_ref()
            .and_then(|v| v.get("symbol"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(symbol, "TEST");

        daemon_task.abort();
        provider_task.abort();
        Ok(())
    }
}
