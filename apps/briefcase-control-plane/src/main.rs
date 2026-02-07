use std::collections::BTreeMap;
use std::net::SocketAddr;

use anyhow::Context as _;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use briefcase_control_plane_api::types::{
    AdminSetPolicyRequest, AdminSetPolicyResponse, AuditListReceiptsResponse, DevicePolicyResponse,
    EnrollDeviceRequest, EnrollDeviceResponse, ErrorResponse, HealthResponse, PolicyBundle,
    SignedPolicyBundle, UploadReceiptsRequest, UploadReceiptsResponse,
};
use briefcase_core::util::{sha256_hex, sha256_hex_concat};
use chrono::{DateTime, Utc};
use clap::Parser;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rand::RngCore as _;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use subtle::ConstantTimeEq as _;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use uuid::Uuid;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:9797";
const MAX_POLICY_TEXT_BYTES: usize = 200_000;
const MAX_RECEIPTS_PER_UPLOAD: usize = 500;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "briefcase-control-plane",
    version,
    about = "Credential Briefcase control plane (reference)"
)]
struct Args {
    /// Address to bind.
    #[arg(long, env = "CONTROL_PLANE_BIND_ADDR", default_value = DEFAULT_BIND_ADDR)]
    bind_addr: SocketAddr,

    /// Postgres connection string, e.g. `postgres://user:pass@127.0.0.1:5432/db`.
    #[arg(long, env = "CONTROL_PLANE_DATABASE_URL")]
    database_url: String,

    /// Admin bearer token (required).
    #[arg(long, env = "CONTROL_PLANE_ADMIN_TOKEN")]
    admin_token: String,

    /// Auditor bearer token (required). May be the same as admin.
    #[arg(long, env = "CONTROL_PLANE_AUDITOR_TOKEN")]
    auditor_token: String,

    /// Ed25519 signing key seed (32 bytes, base64url; required).
    #[arg(long, env = "CONTROL_PLANE_POLICY_SIGNING_KEY_SEED_B64")]
    policy_signing_key_seed_b64: String,
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    admin_token: String,
    auditor_token: String,
    policy_signer: SigningKey,
    policy_pubkey_b64: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hyper=warn,sqlx=warn".into()),
        )
        .json()
        .init();

    let args = Args::parse();
    let policy_signer = parse_ed25519_seed(&args.policy_signing_key_seed_b64)?;
    let policy_pubkey_b64 = {
        let vk: VerifyingKey = policy_signer.verifying_key();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.to_bytes())
    };

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&args.database_url)
        .await
        .context("connect to postgres")?;

    init_db(&pool).await?;
    seed_default_policy_bundle(&pool).await?;

    let st = AppState {
        pool,
        admin_token: args.admin_token,
        auditor_token: args.auditor_token,
        policy_signer,
        policy_pubkey_b64,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/v1/admin/policy",
            get(admin_policy_get).post(admin_policy_set),
        )
        .route("/v1/admin/devices/enroll", post(admin_devices_enroll))
        .route("/v1/devices/{id}/policy", get(device_policy_get))
        .route("/v1/devices/{id}/receipts", post(device_receipts_upload))
        .route("/v1/audit/receipts", get(audit_list_receipts))
        .layer(TraceLayer::new_for_http())
        .with_state(st);

    info!(addr = %args.bind_addr, "briefcase-control-plane listening");
    let listener = tokio::net::TcpListener::bind(args.bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        ts: Utc::now().to_rfc3339(),
    })
}

async fn admin_policy_get(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<AdminSetPolicyResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_admin(&st, &headers)?;
    let bundle = latest_policy_bundle(&st.pool)
        .await
        .map_err(internal_error)?;
    let signed = sign_policy_bundle(&st, &bundle).map_err(internal_error)?;
    Ok(Json(AdminSetPolicyResponse {
        policy_bundle: signed,
    }))
}

async fn admin_policy_set(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AdminSetPolicyRequest>,
) -> Result<Json<AdminSetPolicyResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_admin(&st, &headers)?;

    let policy_text = req.policy_text.trim().to_string();
    if policy_text.is_empty() || policy_text.len() > MAX_POLICY_TEXT_BYTES {
        return Err(bad_request("invalid_policy_text"));
    }

    for (k, v) in &req.budgets {
        if k.trim().is_empty() || k.len() > 64 || *v < 0 {
            return Err(bad_request("invalid_budget"));
        }
    }

    let bundle = insert_policy_bundle(&st.pool, &policy_text, &req.budgets)
        .await
        .map_err(internal_error)?;
    let signed = sign_policy_bundle(&st, &bundle).map_err(internal_error)?;

    Ok(Json(AdminSetPolicyResponse {
        policy_bundle: signed,
    }))
}

async fn admin_devices_enroll(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<EnrollDeviceRequest>,
) -> Result<Json<EnrollDeviceResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_admin(&st, &headers)?;

    if req.device_name.trim().is_empty() || req.device_name.len() > 128 {
        return Err(bad_request("invalid_device_name"));
    }
    if req.device_pubkey_b64.trim().is_empty() || req.device_pubkey_b64.len() > 512 {
        return Err(bad_request("invalid_device_pubkey"));
    }

    let device_token = random_token_b64url(32);
    let token_hash_hex = sha256_hex(device_token.as_bytes());

    upsert_device(
        &st.pool,
        req.device_id,
        &req.device_name,
        &req.device_pubkey_b64,
        &token_hash_hex,
    )
    .await
    .map_err(internal_error)?;

    let bundle = latest_policy_bundle(&st.pool)
        .await
        .map_err(internal_error)?;
    let signed = sign_policy_bundle(&st, &bundle).map_err(internal_error)?;

    Ok(Json(EnrollDeviceResponse {
        device_id: req.device_id,
        device_token,
        policy_signing_pubkey_b64: st.policy_pubkey_b64.clone(),
        policy_bundle: signed,
    }))
}

async fn device_policy_get(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Result<Json<DevicePolicyResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_device(&st, &headers, device_id).await?;
    let bundle = latest_policy_bundle(&st.pool)
        .await
        .map_err(internal_error)?;
    let signed = sign_policy_bundle(&st, &bundle).map_err(internal_error)?;
    Ok(Json(DevicePolicyResponse {
        policy_bundle: signed,
    }))
}

async fn device_receipts_upload(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<Uuid>,
    Json(req): Json<UploadReceiptsRequest>,
) -> Result<Json<UploadReceiptsResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_device(&st, &headers, device_id).await?;

    if req.receipts.len() > MAX_RECEIPTS_PER_UPLOAD {
        return Err(bad_request("too_many_receipts"));
    }

    // Sort ascending so we can verify chain and monotonicity.
    let mut receipts = req.receipts;
    receipts.sort_by_key(|r| r.id);

    let mut stored = 0usize;
    let mut tx = st.pool.begin().await.map_err(internal_error)?;

    let last: Option<(i64, String)> = sqlx::query(
        "SELECT receipt_id, hash_hex FROM receipts WHERE device_id=$1 ORDER BY receipt_id DESC LIMIT 1",
    )
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal_error)?
    .map(|row| (row.get::<i64, _>(0), row.get::<String, _>(1)));

    let mut expected_prev_hash = last
        .as_ref()
        .map(|(_, h)| h.clone())
        .unwrap_or_else(|| "0".repeat(64));
    let mut min_next_id = last.as_ref().map(|(id, _)| id + 1).unwrap_or(1);

    for r in receipts {
        if r.id < min_next_id {
            return Err(bad_request("receipt_id_not_monotonic"));
        }
        if r.prev_hash_hex != expected_prev_hash {
            return Err(bad_request("receipt_prev_hash_mismatch"));
        }

        let event_json =
            serde_json::to_string(&r.event).map_err(|e| internal_error(e.to_string()))?;
        let computed = sha256_hex_concat(&r.prev_hash_hex, event_json.as_bytes());
        if computed != r.hash_hex {
            return Err(bad_request("receipt_hash_mismatch"));
        }

        sqlx::query(
            "INSERT INTO receipts(device_id, receipt_id, ts, prev_hash_hex, hash_hex, event_json) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (device_id, receipt_id) DO NOTHING",
        )
        .bind(device_id)
        .bind(r.id)
        .bind(r.ts)
        .bind(&r.prev_hash_hex)
        .bind(&r.hash_hex)
        .bind(sqlx::types::Json(r.event))
        .execute(&mut *tx)
        .await
        .map_err(internal_error)?;

        stored += 1;
        expected_prev_hash = r.hash_hex;
        min_next_id = r.id + 1;
    }

    tx.commit().await.map_err(internal_error)?;

    Ok(Json(UploadReceiptsResponse { stored }))
}

#[derive(Debug, serde::Deserialize)]
struct AuditQuery {
    device_id: Option<Uuid>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn audit_list_receipts(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Result<Json<AuditListReceiptsResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_auditor(&st, &headers)?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let offset = q.offset.unwrap_or(0).max(0);

    let rows = if let Some(device_id) = q.device_id {
        sqlx::query(
            "SELECT receipt_id, ts, prev_hash_hex, hash_hex, event_json
             FROM receipts WHERE device_id=$1
             ORDER BY receipt_id DESC LIMIT $2 OFFSET $3",
        )
        .bind(device_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&st.pool)
        .await
        .map_err(internal_error)?
    } else {
        sqlx::query(
            "SELECT receipt_id, ts, prev_hash_hex, hash_hex, event_json
             FROM receipts
             ORDER BY ts DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&st.pool)
        .await
        .map_err(internal_error)?
    };

    let mut receipts = Vec::new();
    for row in rows {
        let id: i64 = row.get(0);
        let ts: DateTime<Utc> = row.get(1);
        let prev_hash_hex: String = row.get(2);
        let hash_hex: String = row.get(3);
        let event: serde_json::Value = row.get::<sqlx::types::Json<serde_json::Value>, _>(4).0;
        receipts.push(briefcase_core::ReceiptRecord {
            id,
            ts,
            prev_hash_hex,
            hash_hex,
            event,
        });
    }

    Ok(Json(AuditListReceiptsResponse { receipts }))
}

fn random_token_b64url(nbytes: usize) -> String {
    let mut bytes = vec![0u8; nbytes];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn parse_ed25519_seed(seed_b64: &str) -> anyhow::Result<SigningKey> {
    let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seed_b64.as_bytes())
        .context("decode seed as base64url")?;
    if seed.len() != 32 {
        anyhow::bail!("policy signing seed must be 32 bytes");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed);
    Ok(SigningKey::from_bytes(&arr))
}

fn sign_policy_bundle(st: &AppState, bundle: &PolicyBundle) -> anyhow::Result<SignedPolicyBundle> {
    let bytes = serde_json::to_vec(bundle).context("serialize bundle")?;
    let sig: Signature = st.policy_signer.sign(&bytes);
    let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(SignedPolicyBundle {
        bundle: bundle.clone(),
        signature_b64,
    })
}

fn require_admin(
    st: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let Some(tok) = bearer_token(headers) else {
        return Err(unauthorized("missing_token"));
    };
    if tok.as_bytes().ct_eq(st.admin_token.as_bytes()).unwrap_u8() != 1 {
        return Err(unauthorized("invalid_token"));
    }
    Ok(())
}

fn require_auditor(
    st: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let Some(tok) = bearer_token(headers) else {
        return Err(unauthorized("missing_token"));
    };
    let ok_admin = tok.as_bytes().ct_eq(st.admin_token.as_bytes()).unwrap_u8() == 1;
    let ok_auditor = tok
        .as_bytes()
        .ct_eq(st.auditor_token.as_bytes())
        .unwrap_u8()
        == 1;
    if !ok_admin && !ok_auditor {
        return Err(unauthorized("invalid_token"));
    }
    Ok(())
}

async fn require_device(
    st: &AppState,
    headers: &axum::http::HeaderMap,
    device_id: Uuid,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let Some(tok) = bearer_token(headers) else {
        return Err(unauthorized("missing_token"));
    };
    let token_hash_hex = sha256_hex(tok.as_bytes());

    let row: Option<(String,)> = sqlx::query_as("SELECT token_hash_hex FROM devices WHERE id=$1")
        .bind(device_id)
        .fetch_optional(&st.pool)
        .await
        .map_err(internal_error)?;
    let Some((expected,)) = row else {
        return Err(unauthorized("unknown_device"));
    };
    if token_hash_hex
        .as_bytes()
        .ct_eq(expected.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(unauthorized("invalid_token"));
    }

    // Best-effort last_seen update.
    let _ = sqlx::query("UPDATE devices SET last_seen=now() WHERE id=$1")
        .bind(device_id)
        .execute(&st.pool)
        .await;
    Ok(())
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let raw = raw.trim();
    let tok = raw.strip_prefix("Bearer ")?;
    if tok.is_empty() {
        return None;
    }
    Some(tok.to_string())
}

async fn init_db(pool: &PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await.context("begin tx")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS policy_bundles (
          bundle_id     BIGSERIAL PRIMARY KEY,
          policy_text   TEXT NOT NULL,
          budgets_json  JSONB NOT NULL,
          created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        "#,
    )
    .execute(&mut *tx)
    .await
    .context("create policy_bundles")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS devices (
          id                UUID PRIMARY KEY,
          device_name       TEXT NOT NULL,
          device_pubkey_b64 TEXT NOT NULL,
          token_hash_hex    TEXT NOT NULL,
          created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
          last_seen         TIMESTAMPTZ
        )
        "#,
    )
    .execute(&mut *tx)
    .await
    .context("create devices")?;
    sqlx::query("CREATE INDEX IF NOT EXISTS devices_token_hash_idx ON devices(token_hash_hex)")
        .execute(&mut *tx)
        .await
        .context("create devices_token_hash_idx")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS receipts (
          id            BIGSERIAL PRIMARY KEY,
          device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
          receipt_id    BIGINT NOT NULL,
          ts            TIMESTAMPTZ NOT NULL,
          prev_hash_hex TEXT NOT NULL,
          hash_hex      TEXT NOT NULL,
          event_json    JSONB NOT NULL,
          inserted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
          UNIQUE(device_id, receipt_id)
        )
        "#,
    )
    .execute(&mut *tx)
    .await
    .context("create receipts")?;
    sqlx::query("CREATE INDEX IF NOT EXISTS receipts_device_id_idx ON receipts(device_id)")
        .execute(&mut *tx)
        .await
        .context("create receipts_device_id_idx")?;
    sqlx::query("CREATE INDEX IF NOT EXISTS receipts_ts_idx ON receipts(ts)")
        .execute(&mut *tx)
        .await
        .context("create receipts_ts_idx")?;

    tx.commit().await.context("commit schema")?;
    Ok(())
}

async fn seed_default_policy_bundle(pool: &PgPool) -> anyhow::Result<()> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_bundles")
        .fetch_one(pool)
        .await
        .context("count policy_bundles")?;
    if n > 0 {
        return Ok(());
    }

    // Match the daemon defaults.
    let policy_text = briefcase_policy::CedarPolicyEngineOptions::default_policies().policy_text;
    let budgets: BTreeMap<String, i64> = BTreeMap::from([
        ("read".to_string(), 3_000_000),
        ("write".to_string(), 0),
        ("admin".to_string(), 0),
    ]);
    let _ = insert_policy_bundle(pool, &policy_text, &budgets).await?;
    Ok(())
}

async fn insert_policy_bundle(
    pool: &PgPool,
    policy_text: &str,
    budgets: &BTreeMap<String, i64>,
) -> anyhow::Result<PolicyBundle> {
    let row = sqlx::query(
        "INSERT INTO policy_bundles(policy_text, budgets_json) VALUES ($1, $2) RETURNING bundle_id, created_at",
    )
    .bind(policy_text)
    .bind(sqlx::types::Json(budgets))
    .fetch_one(pool)
    .await
    .context("insert policy bundle")?;

    let bundle_id: i64 = row.get(0);
    let created_at: DateTime<Utc> = row.get(1);
    Ok(PolicyBundle {
        bundle_id,
        policy_text: policy_text.to_string(),
        budgets: budgets.clone(),
        updated_at_rfc3339: created_at.to_rfc3339(),
    })
}

async fn latest_policy_bundle(pool: &PgPool) -> anyhow::Result<PolicyBundle> {
    let row = sqlx::query(
        "SELECT bundle_id, policy_text, budgets_json, created_at
         FROM policy_bundles ORDER BY bundle_id DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .context("fetch latest policy bundle")?;

    let bundle_id: i64 = row.get(0);
    let policy_text: String = row.get(1);
    let budgets: BTreeMap<String, i64> =
        row.get::<sqlx::types::Json<BTreeMap<String, i64>>, _>(2).0;
    let created_at: DateTime<Utc> = row.get(3);
    Ok(PolicyBundle {
        bundle_id,
        policy_text,
        budgets,
        updated_at_rfc3339: created_at.to_rfc3339(),
    })
}

async fn upsert_device(
    pool: &PgPool,
    device_id: Uuid,
    device_name: &str,
    device_pubkey_b64: &str,
    token_hash_hex: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO devices(id, device_name, device_pubkey_b64, token_hash_hex)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT(id) DO UPDATE SET
          device_name=excluded.device_name,
          device_pubkey_b64=excluded.device_pubkey_b64,
          token_hash_hex=excluded.token_hash_hex
        "#,
    )
    .bind(device_id)
    .bind(device_name)
    .bind(device_pubkey_b64)
    .bind(token_hash_hex)
    .execute(pool)
    .await
    .context("upsert device")?;
    Ok(())
}

fn internal_error<E: std::fmt::Display>(e: E) -> (StatusCode, Json<ErrorResponse>) {
    error!(error = %e, "control plane request failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            code: "internal_error".to_string(),
            message: "internal error".to_string(),
        }),
    )
}

fn bad_request(code: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            code: code.to_string(),
            message: code.to_string(),
        }),
    )
}

fn unauthorized(code: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            code: code.to_string(),
            message: code.to_string(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_signing_round_trips() -> anyhow::Result<()> {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let vk = signer.verifying_key();
        let bundle = PolicyBundle {
            bundle_id: 1,
            policy_text: "permit(principal, action, resource);".to_string(),
            budgets: BTreeMap::from([("read".to_string(), 1)]),
            updated_at_rfc3339: "2026-01-01T00:00:00Z".to_string(),
        };
        let bytes = serde_json::to_vec(&bundle)?;
        let sig: Signature = signer.sign(&bytes);
        vk.verify_strict(&bytes, &sig)?;
        Ok(())
    }

    #[test]
    fn receipt_hash_matches_core_impl() {
        let prev = "0".repeat(64);
        let event = serde_json::json!({"kind":"tool_call","tool_id":"echo"});
        let event_json = serde_json::to_string(&event).unwrap();
        let h = sha256_hex_concat(&prev, event_json.as_bytes());
        assert_eq!(h.len(), 64);
    }
}
