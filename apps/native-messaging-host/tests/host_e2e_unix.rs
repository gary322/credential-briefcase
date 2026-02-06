#![cfg(unix)]

use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::time::{Duration, timeout};

#[derive(Debug, Clone)]
struct StubState {
    auth_token: String,
    calls: Arc<tokio::sync::Mutex<Vec<String>>>,
}

fn require_auth(headers: &HeaderMap, st: &StubState) -> bool {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .map(|v| v == format!("Bearer {}", st.auth_token))
        .unwrap_or(false)
}

async fn health(
    State(st): State<StubState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push("health".to_string());
    (StatusCode::OK, Json(serde_json::json!({"status":"ok"})))
}

#[derive(Debug, Serialize)]
struct ListMcpServersResponse {
    servers: Vec<McpServerSummary>,
}

#[derive(Debug, Serialize)]
struct McpServerSummary {
    id: String,
    endpoint_url: String,
    has_oauth_refresh: bool,
}

async fn list_mcp_servers(
    State(st): State<StubState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push("list_mcp_servers".to_string());
    (
        StatusCode::OK,
        Json(serde_json::to_value(ListMcpServersResponse { servers: vec![] }).unwrap()),
    )
}

#[derive(Debug, Deserialize)]
struct UpsertMcpServerRequest {
    endpoint_url: String,
}

async fn upsert_mcp_server(
    State(st): State<StubState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpsertMcpServerRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls
        .lock()
        .await
        .push(format!("upsert_mcp_server:{id}:{}", req.endpoint_url));
    (
        StatusCode::OK,
        Json(
            serde_json::to_value(McpServerSummary {
                id,
                endpoint_url: req.endpoint_url,
                has_oauth_refresh: false,
            })
            .unwrap(),
        ),
    )
}

#[derive(Debug, Deserialize)]
struct McpOAuthStartRequest {
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct McpOAuthStartResponse {
    server_id: String,
    authorization_url: String,
    state: String,
}

async fn mcp_oauth_start(
    State(st): State<StubState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<McpOAuthStartRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push(format!(
        "mcp_oauth_start:{id}:client_id={}:redirect_uri={}:scope={}",
        req.client_id,
        req.redirect_uri,
        req.scope.clone().unwrap_or_default()
    ));
    (
        StatusCode::OK,
        Json(
            serde_json::to_value(McpOAuthStartResponse {
                server_id: id,
                authorization_url: "https://example.invalid/authorize".to_string(),
                state: "state_mock".to_string(),
            })
            .unwrap(),
        ),
    )
}

#[derive(Debug, Deserialize)]
struct McpOAuthExchangeRequest {
    code: String,
    state: String,
}

async fn mcp_oauth_exchange(
    State(st): State<StubState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<McpOAuthExchangeRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push(format!(
        "mcp_oauth_exchange:{id}:code={}:state={}",
        req.code, req.state
    ));
    (StatusCode::OK, Json(serde_json::json!({ "server_id": id })))
}

async fn start_stub_daemon(
    socket_path: &std::path::Path,
    auth_token: String,
) -> anyhow::Result<(StubState, tokio::task::JoinHandle<()>)> {
    let st = StubState {
        auth_token,
        calls: Arc::new(tokio::sync::Mutex::new(Vec::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/mcp/servers", get(list_mcp_servers))
        .route("/v1/mcp/servers/{id}", post(upsert_mcp_server))
        .route("/v1/mcp/servers/{id}/oauth/start", post(mcp_oauth_start))
        .route(
            "/v1/mcp/servers/{id}/oauth/exchange",
            post(mcp_oauth_exchange),
        )
        .with_state(st.clone());

    let listener = tokio::net::UnixListener::bind(socket_path).context("bind unix socket")?;
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok((st, handle))
}

async fn send_native(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    msg: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let bytes = serde_json::to_vec(&msg).context("encode request")?;
    let len: u32 = bytes.len().try_into().context("len fits u32")?;
    writer
        .write_all(&len.to_le_bytes())
        .await
        .context("write len")?;
    writer.write_all(&bytes).await.context("write bytes")?;
    writer.flush().await.context("flush")?;

    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("read resp len")?;
    let rlen = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; rlen];
    reader.read_exact(&mut buf).await.context("read resp")?;
    serde_json::from_slice(&buf).context("decode resp")
}

#[tokio::test]
async fn native_messaging_host_forwards_mcp_oauth_calls_over_unix_socket() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let data_dir = dir.path();
    let sock_path = data_dir.join("briefcased.sock");

    let auth_token = "test-token";

    let (st, daemon_task) = start_stub_daemon(&sock_path, auth_token.to_string()).await?;

    let client = briefcase_api::BriefcaseClient::new(
        briefcase_api::DaemonEndpoint::Unix {
            socket_path: sock_path.clone(),
        },
        auth_token.to_string(),
    );

    let (ext_io, host_io) = tokio::io::duplex(1024 * 64);
    let (mut ext_r, mut ext_w) = tokio::io::split(ext_io);
    let (mut host_r, mut host_w) = tokio::io::split(host_io);

    let host_task = tokio::spawn(async move {
        native_messaging_host::run_native_messaging_host(&client, &mut host_r, &mut host_w).await
    });

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "1",
                "method": "health",
                "params": {}
            }),
        ),
    )
    .await
    .context("timeout: native health")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("1"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "2",
                "method": "upsert_mcp_server",
                "params": {
                    "server_id": "s1",
                    "endpoint_url": "http://127.0.0.1:1234/mcp"
                }
            }),
        ),
    )
    .await
    .context("timeout: native upsert_mcp_server")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("2"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "3",
                "method": "mcp_oauth_start",
                "params": {
                    "server_id": "s1",
                    "client_id": "briefcase-extension",
                    "redirect_uri": "https://example.invalid/callback",
                    "scope": "mcp.read"
                }
            }),
        ),
    )
    .await
    .context("timeout: native mcp_oauth_start")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("3"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let state = resp
        .get("result")
        .and_then(|v| v.get("state"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert_eq!(state, "state_mock");

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "4",
                "method": "mcp_oauth_exchange",
                "params": {
                    "server_id": "s1",
                    "code": "code_mock",
                    "state": state
                }
            }),
        ),
    )
    .await
    .context("timeout: native mcp_oauth_exchange")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("4"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let calls = st.calls.lock().await.clone();
    assert!(
        calls.iter().any(|c| c == "health"),
        "missing health call: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|c| c == "upsert_mcp_server:s1:http://127.0.0.1:1234/mcp"),
        "missing upsert call: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c.contains("mcp_oauth_start:s1:")),
        "missing oauth_start call: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|c| c == "mcp_oauth_exchange:s1:code=code_mock:state=state_mock"),
        "missing oauth_exchange call: {calls:?}"
    );

    drop(ext_w);
    drop(ext_r);
    timeout(Duration::from_secs(10), host_task)
        .await
        .context("timeout: join native host task")?
        .context("join native host task")?
        .context("native host loop")?;
    daemon_task.abort();
    Ok(())
}
