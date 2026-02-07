#![cfg(unix)]

use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::time::{Duration, timeout};
use uuid::Uuid;

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

async fn delete_mcp_server(
    State(st): State<StubState>,
    headers: HeaderMap,
    Path(id): Path<String>,
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
        .push(format!("delete_mcp_server:{id}"));
    (StatusCode::OK, Json(serde_json::json!({ "server_id": id })))
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

#[derive(Debug, Serialize)]
struct ListProvidersResponse {
    providers: Vec<ProviderSummary>,
}

#[derive(Debug, Serialize)]
struct ProviderSummary {
    id: String,
    base_url: String,
    has_oauth_refresh: bool,
    has_vc: bool,
    vc_expires_at_rfc3339: Option<String>,
}

async fn list_providers(
    State(st): State<StubState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push("list_providers".to_string());
    (
        StatusCode::OK,
        Json(serde_json::to_value(ListProvidersResponse { providers: vec![] }).unwrap()),
    )
}

#[derive(Debug, Deserialize)]
struct UpsertProviderRequest {
    base_url: String,
}

async fn upsert_provider(
    State(st): State<StubState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpsertProviderRequest>,
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
        .push(format!("upsert_provider:{id}:{}", req.base_url));
    (
        StatusCode::OK,
        Json(
            serde_json::to_value(ProviderSummary {
                id,
                base_url: req.base_url,
                has_oauth_refresh: false,
                has_vc: false,
                vc_expires_at_rfc3339: None,
            })
            .unwrap(),
        ),
    )
}

async fn fetch_vc(
    State(st): State<StubState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push(format!("fetch_vc:{id}"));
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "provider_id": id,
            "expires_at_rfc3339": "2026-12-31T00:00:00Z"
        })),
    )
}

async fn delete_provider(
    State(st): State<StubState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push(format!("delete_provider:{id}"));
    (
        StatusCode::OK,
        Json(serde_json::json!({ "provider_id": id })),
    )
}

#[derive(Debug, Serialize)]
struct ListBudgetsResponse {
    budgets: Vec<BudgetRecord>,
}

#[derive(Debug, Serialize)]
struct BudgetRecord {
    category: String,
    daily_limit_microusd: i64,
}

async fn list_budgets(
    State(st): State<StubState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push("list_budgets".to_string());
    (
        StatusCode::OK,
        Json(serde_json::to_value(ListBudgetsResponse { budgets: vec![] }).unwrap()),
    )
}

#[derive(Debug, Deserialize)]
struct SetBudgetRequest {
    daily_limit_microusd: i64,
}

async fn set_budget(
    State(st): State<StubState>,
    headers: HeaderMap,
    Path(category): Path<String>,
    Json(req): Json<SetBudgetRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push(format!(
        "set_budget:{category}:{}",
        req.daily_limit_microusd
    ));
    (
        StatusCode::OK,
        Json(
            serde_json::to_value(BudgetRecord {
                category,
                daily_limit_microusd: req.daily_limit_microusd,
            })
            .unwrap(),
        ),
    )
}

#[derive(Debug, Serialize)]
struct ListApprovalsResponse {
    approvals: Vec<briefcase_core::ApprovalRequest>,
}

async fn list_approvals(
    State(st): State<StubState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push("list_approvals".to_string());

    let approval = briefcase_core::ApprovalRequest {
        id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
        created_at: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        expires_at: DateTime::parse_from_rfc3339("2026-01-01T00:10:00Z")
            .unwrap()
            .with_timezone(&Utc),
        tool_id: "demo.write".to_string(),
        reason: "requires_approval".to_string(),
        kind: briefcase_core::ApprovalKind::Local,
        summary: serde_json::json!({"action":"write"}),
    };

    (
        StatusCode::OK,
        Json(
            serde_json::to_value(ListApprovalsResponse {
                approvals: vec![approval],
            })
            .unwrap(),
        ),
    )
}

async fn approve(
    State(st): State<StubState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push(format!("approve:{id}"));
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "approval_id": id,
            "approval_token": "token_mock"
        })),
    )
}

#[derive(Debug, Serialize)]
struct ListReceiptsResponse {
    receipts: Vec<briefcase_core::ReceiptRecord>,
}

async fn list_receipts(
    State(st): State<StubState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push("list_receipts".to_string());

    let r = briefcase_core::ReceiptRecord {
        id: 1,
        ts: DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        prev_hash_hex: "00".to_string(),
        hash_hex: "11".to_string(),
        event: serde_json::json!({"kind":"tool_call","tool_id":"demo.read","ok":true}),
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(ListReceiptsResponse { receipts: vec![r] }).unwrap()),
    )
}

async fn verify_receipts(
    State(st): State<StubState>,
    headers: HeaderMap,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_auth(&headers, &st) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"code":"unauthorized","message":"unauthorized"})),
        );
    }
    st.calls.lock().await.push("verify_receipts".to_string());
    (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
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
        .route("/v1/mcp/servers/{id}/delete", post(delete_mcp_server))
        .route("/v1/mcp/servers/{id}/oauth/start", post(mcp_oauth_start))
        .route(
            "/v1/mcp/servers/{id}/oauth/exchange",
            post(mcp_oauth_exchange),
        )
        .route("/v1/providers", get(list_providers))
        .route("/v1/providers/{id}", post(upsert_provider))
        .route("/v1/providers/{id}/vc/fetch", post(fetch_vc))
        .route("/v1/providers/{id}/delete", post(delete_provider))
        .route("/v1/budgets", get(list_budgets))
        .route("/v1/budgets/{category}", post(set_budget))
        .route("/v1/approvals", get(list_approvals))
        .route("/v1/approvals/{id}/approve", post(approve))
        .route("/v1/receipts", get(list_receipts))
        .route("/v1/receipts/verify", post(verify_receipts))
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

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "5",
                "method": "upsert_provider",
                "params": {
                    "provider_id": "p1",
                    "base_url": "http://127.0.0.1:9099"
                }
            }),
        ),
    )
    .await
    .context("timeout: native upsert_provider")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("5"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "6",
                "method": "fetch_vc",
                "params": {
                    "provider_id": "p1"
                }
            }),
        ),
    )
    .await
    .context("timeout: native fetch_vc")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("6"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "7",
                "method": "set_budget",
                "params": {
                    "category": "research",
                    "daily_limit_microusd": 123
                }
            }),
        ),
    )
    .await
    .context("timeout: native set_budget")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("7"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "8",
                "method": "list_approvals",
                "params": {}
            }),
        ),
    )
    .await
    .context("timeout: native list_approvals")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("8"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "9",
                "method": "approve",
                "params": {
                    "id": "00000000-0000-0000-0000-000000000000"
                }
            }),
        ),
    )
    .await
    .context("timeout: native approve")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("9"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "10",
                "method": "list_receipts",
                "params": {
                    "limit": 50,
                    "offset": 0
                }
            }),
        ),
    )
    .await
    .context("timeout: native list_receipts")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("10"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "11",
                "method": "verify_receipts",
                "params": {}
            }),
        ),
    )
    .await
    .context("timeout: native verify_receipts")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("11"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "12",
                "method": "delete_provider",
                "params": {
                    "provider_id": "p1"
                }
            }),
        ),
    )
    .await
    .context("timeout: native delete_provider")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("12"));
    assert_eq!(resp.get("ok").and_then(|v| v.as_bool()), Some(true));

    let resp = timeout(
        Duration::from_secs(10),
        send_native(
            &mut ext_w,
            &mut ext_r,
            serde_json::json!({
                "id": "13",
                "method": "delete_mcp_server",
                "params": {
                    "server_id": "s1"
                }
            }),
        ),
    )
    .await
    .context("timeout: native delete_mcp_server")??;
    assert_eq!(resp.get("id").and_then(|v| v.as_str()), Some("13"));
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
    assert!(
        calls
            .iter()
            .any(|c| c == "upsert_provider:p1:http://127.0.0.1:9099"),
        "missing upsert_provider call: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "fetch_vc:p1"),
        "missing fetch_vc call: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "set_budget:research:123"),
        "missing set_budget call: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "list_approvals"),
        "missing list_approvals call: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|c| c == "approve:00000000-0000-0000-0000-000000000000"),
        "missing approve call: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "list_receipts"),
        "missing list_receipts call: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "verify_receipts"),
        "missing verify_receipts call: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "delete_provider:p1"),
        "missing delete_provider call: {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "delete_mcp_server:s1"),
        "missing delete_mcp_server call: {calls:?}"
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
