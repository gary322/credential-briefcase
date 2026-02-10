use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Body;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use briefcase_core::COMPATIBILITY_PROFILE_VERSION;
use briefcase_dpop::{jwk_thumbprint_b64url, verify_dpop_jwt};
use briefcase_payments::x402 as x402_v2;
use chrono::{DateTime, Utc};
use clap::Parser;
use hmac::{Hmac, Mac};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use rand::{Rng as _, RngCore as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;
use tracing::info;
use url::Url;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const HEADER_BRIEFCASE_ERROR: &str = "x-briefcase-error";
const HEADER_BRIEFCASE_COMPATIBILITY_PROFILE: &str = "x-briefcase-compatibility-profile";
const BRIEFCASE_ERROR_CAPABILITY_REVOKED: &str = "capability_revoked";
const BRIEFCASE_ERROR_REPLAY_DETECTED: &str = "replay_detected";
const HEADER_AAG_ADMIN_SECRET: &str = "x-aag-admin-secret";
const MAX_DPOP_REPLAY_ENTRIES: usize = 20_000;
const MAX_X402_NONCE_ENTRIES: usize = 20_000;

// x402 v2 offer defaults for the reference provider gateway.
const X402_V2_NETWORK: &str = "eip155:84532"; // Base Sepolia
const X402_V2_ASSET: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"; // USDC (Base Sepolia)
const X402_V2_PAY_TO: &str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const X402_V2_TOKEN_NAME: &str = "USD Coin";
const X402_V2_TOKEN_VERSION: &str = "2";
const X402_V2_MAX_TIMEOUT_SECONDS: i64 = 60;

#[derive(Debug, Clone, clap::ValueEnum, PartialEq, Eq)]
#[clap(rename_all = "snake_case")]
enum L402Backend {
    Demo,
    Lnd,
    Cln,
}

#[derive(Debug, Parser)]
#[command(
    name = "agent-access-gateway",
    version,
    about = "Reference provider-side gateway"
)]
struct Args {
    #[arg(long, env = "AAG_ADDR", default_value = "127.0.0.1:9099")]
    addr: SocketAddr,

    /// HMAC secret for signing capability JWTs and payment proofs.
    #[arg(long, env = "AAG_SECRET", default_value = "dev-secret-change-me")]
    secret: String,

    #[arg(long, env = "AAG_COST_MICROUSD", default_value_t = 2000)]
    cost_microusd: i64,

    #[arg(long, env = "AAG_MAX_CALLS", default_value_t = 50)]
    max_calls: i64,

    /// L402 backend for issuing invoices and verifying payments.
    ///
    /// `demo` keeps the existing in-memory behavior. `lnd` and `cln` connect to a
    /// regtest Lightning node and issue real BOLT11 invoices.
    #[arg(long, env = "AAG_L402_BACKEND", default_value = "demo")]
    l402_backend: L402Backend,

    /// Amount to request on Lightning invoices, in satoshis.
    #[arg(long, env = "AAG_L402_INVOICE_SATS", default_value_t = 10)]
    l402_invoice_sats: i64,

    /// LND gRPC endpoint for the provider's node, e.g. `https://localhost:10009`.
    #[arg(long, env = "AAG_LND_GRPC_ENDPOINT")]
    lnd_grpc_endpoint: Option<String>,

    /// LND TLS cert file for the provider's node.
    #[arg(long, env = "AAG_LND_TLS_CERT_FILE")]
    lnd_tls_cert_file: Option<PathBuf>,

    /// LND admin macaroon file for the provider's node.
    #[arg(long, env = "AAG_LND_MACAROON_FILE")]
    lnd_macaroon_file: Option<PathBuf>,

    /// Override the TLS SNI/hostname used for LND certificate verification.
    #[arg(long, env = "AAG_LND_TLS_DOMAIN")]
    lnd_tls_domain: Option<String>,

    /// Core Lightning JSON-RPC socket for the provider's node.
    #[arg(long, env = "AAG_CLN_RPC_SOCKET")]
    cln_rpc_socket: Option<PathBuf>,
}

#[derive(Clone)]
struct AppState {
    secret: Vec<u8>,
    cost_microusd: i64,
    max_calls: i64,
    l402_backend: L402Backend,
    // Only used when real L402 backends are enabled; keep the config fields
    // present so CLI/env remains stable across builds.
    #[allow(dead_code)]
    l402_invoice_sats: i64,
    #[allow(dead_code)]
    lnd: Option<LndProviderConfig>,
    #[allow(dead_code)]
    cln_rpc_socket: Option<PathBuf>,
    pending_x402: Arc<Mutex<HashMap<String, PendingPayment>>>,
    pending_l402: Arc<Mutex<HashMap<String, PendingL402>>>,
    usage: Arc<Mutex<HashMap<String, i64>>>, // jti -> calls
    revoked_cap_jtis: Arc<Mutex<HashMap<String, i64>>>, // jti -> revoked_at (unix seconds)
    used_dpop_jtis: Arc<Mutex<HashMap<String, i64>>>, // `${jkt}:${jti}` -> iat
    used_x402_nonces: Arc<Mutex<HashMap<String, i64>>>, // nonce -> iat
    oauth_codes: Arc<Mutex<HashMap<String, OAuthCode>>>, // code -> record
    oauth_refresh: Arc<Mutex<HashMap<String, OAuthRefresh>>>, // refresh -> record
    oauth_access: Arc<Mutex<HashMap<String, OAuthAccess>>>, // access -> record
}

#[derive(Debug, Clone)]
struct PendingPayment {
    paid: bool,
}

#[derive(Clone)]
struct LndProviderConfig {
    endpoint: String,
    tls_cert_pem: Vec<u8>,
    macaroon_hex: String,
    tls_domain: String,
}

impl std::fmt::Debug for LndProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LndProviderConfig")
            .field("endpoint", &self.endpoint)
            .field("tls_domain", &self.tls_domain)
            .field("tls_cert_pem_len", &self.tls_cert_pem.len())
            .field("macaroon_hex_len", &self.macaroon_hex.len())
            .finish()
    }
}

#[derive(Debug, Clone)]
enum PendingL402 {
    Demo {
        preimage: String,
        created_at: DateTime<Utc>,
    },
    #[allow(dead_code)]
    Lightning {
        payment_hash_hex: String,
        created_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone)]
struct OAuthCode {
    code_challenge: String,
    redirect_uri: String,
    client_id: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct OAuthRefresh {
    client_id: String,
    scope: String,
}

#[derive(Debug, Clone)]
struct OAuthAccess {
    client_id: String,
    scope: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    token: String,
    expires_at_rfc3339: String,
    max_calls: i64,
    compatibility_profile: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "rail", rename_all = "snake_case")]
enum PaymentChallenge {
    X402 {
        payment_id: String,
        payment_url: String,
        amount_microusd: i64,
    },
    L402 {
        invoice: String,
        macaroon: String,
        amount_microusd: i64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct PayRequest {
    payment_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PayResponse {
    /// Proof format: `<payment_id>:<sig_b64url>`
    proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct L402PayRequest {
    invoice: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct L402PayResponse {
    preimage: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CapabilityClaims {
    exp: usize,
    iat: usize,
    jti: String,
    scope: String,
    max_calls: i64,
    cost_microusd: i64,
    /// If set, requests must include a valid DPoP proof whose JWK thumbprint matches `cnf.jkt`.
    cnf: Option<CapabilityCnf>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CapabilityCnf {
    jkt: String,
}

#[derive(Debug, Deserialize)]
struct QuoteQuery {
    symbol: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct RevokeRequest {
    /// Capability `jti` to revoke.
    jti: Option<String>,
    /// Capability token to revoke (decoded to extract `jti`).
    token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
struct RevokeResponse {
    revoked: bool,
    jti: String,
}

#[derive(Debug, Deserialize)]
struct OAuthAuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthTokenForm {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: Option<String>,
    scope: String,
}

#[derive(Debug, Deserialize)]
struct VcIssueQuery {
    holder_did: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct VcIssueResponse {
    vc_jwt: String,
    expires_at_rfc3339: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct VcClaims {
    exp: usize,
    iat: usize,
    iss: String,
    sub: String,
    scope: String,
    tier: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hyper=warn".into()),
        )
        .json()
        .init();

    let args = Args::parse();
    if args.l402_invoice_sats <= 0 {
        anyhow::bail!("--l402-invoice-sats must be > 0");
    }

    let lnd = if args.l402_backend == L402Backend::Lnd {
        if !cfg!(feature = "l402-lnd") {
            anyhow::bail!(
                "built without l402-lnd feature; rebuild agent-access-gateway with --features l402-lnd"
            );
        }

        let endpoint = args
            .lnd_grpc_endpoint
            .clone()
            .context("missing --lnd-grpc-endpoint / AAG_LND_GRPC_ENDPOINT")?;
        let url = Url::parse(&endpoint).context("parse lnd grpc endpoint")?;
        if url.scheme() != "https" {
            anyhow::bail!("lnd grpc endpoint must be https");
        }

        let tls_domain = args
            .lnd_tls_domain
            .clone()
            .unwrap_or_else(|| url.host_str().unwrap_or("localhost").to_string());

        let tls_cert_file = args
            .lnd_tls_cert_file
            .as_ref()
            .context("missing --lnd-tls-cert-file / AAG_LND_TLS_CERT_FILE")?;
        let tls_cert_pem = std::fs::read(tls_cert_file)
            .with_context(|| format!("read lnd tls cert {}", tls_cert_file.display()))?;

        let macaroon_file = args
            .lnd_macaroon_file
            .as_ref()
            .context("missing --lnd-macaroon-file / AAG_LND_MACAROON_FILE")?;
        let macaroon = std::fs::read(macaroon_file)
            .with_context(|| format!("read lnd macaroon {}", macaroon_file.display()))?;
        let macaroon_hex = hex::encode(macaroon);

        Some(LndProviderConfig {
            endpoint,
            tls_cert_pem,
            macaroon_hex,
            tls_domain,
        })
    } else {
        None
    };

    let cln_rpc_socket = if args.l402_backend == L402Backend::Cln {
        if !cfg!(all(feature = "l402-cln", unix)) {
            anyhow::bail!(
                "built without l402-cln feature (unix only); rebuild agent-access-gateway with --features l402-cln"
            );
        }

        Some(
            args.cln_rpc_socket
                .clone()
                .context("missing --cln-rpc-socket / AAG_CLN_RPC_SOCKET")?,
        )
    } else {
        None
    };

    let st = AppState {
        secret: args.secret.as_bytes().to_vec(),
        cost_microusd: args.cost_microusd,
        max_calls: args.max_calls,
        l402_backend: args.l402_backend,
        l402_invoice_sats: args.l402_invoice_sats,
        lnd,
        cln_rpc_socket,
        pending_x402: Arc::new(Mutex::new(HashMap::new())),
        pending_l402: Arc::new(Mutex::new(HashMap::new())),
        usage: Arc::new(Mutex::new(HashMap::new())),
        revoked_cap_jtis: Arc::new(Mutex::new(HashMap::new())),
        used_dpop_jtis: Arc::new(Mutex::new(HashMap::new())),
        used_x402_nonces: Arc::new(Mutex::new(HashMap::new())),
        oauth_codes: Arc::new(Mutex::new(HashMap::new())),
        oauth_refresh: Arc::new(Mutex::new(HashMap::new())),
        oauth_access: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/token", post(token))
        .route("/pay", post(pay))
        .route("/l402/pay", post(l402_pay))
        .route("/oauth/authorize", get(oauth_authorize))
        .route("/oauth/token", post(oauth_token))
        .route("/vc/issue", post(vc_issue))
        .route("/api/revoke", post(revoke))
        .route("/api/quote", get(quote))
        .layer(axum::middleware::from_fn(attach_profile_headers))
        .layer(TraceLayer::new_for_http())
        .with_state(st);

    info!(addr = %args.addr, "agent-access-gateway listening");
    let listener = tokio::net::TcpListener::bind(args.addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"ok"}))
}

async fn attach_profile_headers(req: Request<Body>, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        HEADER_BRIEFCASE_COMPATIBILITY_PROFILE,
        HeaderValue::from_static(COMPATIBILITY_PROFILE_VERSION),
    );
    resp
}

fn briefcase_error(status: StatusCode, code: &'static str) -> Response {
    let mut resp = (status, Json(serde_json::json!({ "error": code }))).into_response();
    resp.headers_mut()
        .insert(HEADER_BRIEFCASE_ERROR, HeaderValue::from_static(code));
    resp
}

async fn oauth_authorize(
    State(st): State<AppState>,
    Query(q): Query<OAuthAuthorizeQuery>,
) -> Result<Redirect, StatusCode> {
    if q.response_type != "code" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let method_ok = q
        .code_challenge_method
        .as_deref()
        .map(|m| m.eq_ignore_ascii_case("S256"))
        .unwrap_or(false);
    if !method_ok {
        return Err(StatusCode::BAD_REQUEST);
    }

    if q.code_challenge.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let code = Uuid::new_v4().to_string();
    let rec = OAuthCode {
        code_challenge: q.code_challenge,
        redirect_uri: q.redirect_uri.clone(),
        client_id: q.client_id,
        expires_at: Utc::now() + chrono::Duration::minutes(5),
    };
    st.oauth_codes.lock().await.insert(code.clone(), rec);

    let mut u = Url::parse(&q.redirect_uri).map_err(|_| StatusCode::BAD_REQUEST)?;
    u.query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &q.state);
    Ok(Redirect::temporary(u.as_str()))
}

async fn oauth_token(
    State(st): State<AppState>,
    Form(form): Form<OAuthTokenForm>,
) -> Result<Json<OAuthTokenResponse>, StatusCode> {
    match form.grant_type.as_str() {
        "authorization_code" => {
            let code = form.code.ok_or(StatusCode::BAD_REQUEST)?;
            let redirect_uri = form.redirect_uri.ok_or(StatusCode::BAD_REQUEST)?;
            let client_id = form.client_id.ok_or(StatusCode::BAD_REQUEST)?;
            let code_verifier = form.code_verifier.ok_or(StatusCode::BAD_REQUEST)?;

            let rec = st
                .oauth_codes
                .lock()
                .await
                .remove(&code)
                .ok_or(StatusCode::BAD_REQUEST)?;
            if Utc::now() > rec.expires_at {
                return Err(StatusCode::BAD_REQUEST);
            }
            if rec.redirect_uri != redirect_uri {
                return Err(StatusCode::BAD_REQUEST);
            }
            if rec.client_id != client_id {
                return Err(StatusCode::BAD_REQUEST);
            }

            let expected = pkce_s256(&code_verifier);
            if expected != rec.code_challenge {
                return Err(StatusCode::BAD_REQUEST);
            }

            let scope = "quote".to_string();
            let (access_token, refresh_token) = issue_oauth_tokens(&st, &client_id, &scope).await;
            Ok(Json(OAuthTokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: 600,
                refresh_token: Some(refresh_token),
                scope,
            }))
        }
        "refresh_token" => {
            let refresh_token = form.refresh_token.ok_or(StatusCode::BAD_REQUEST)?;
            let client_id = form.client_id.ok_or(StatusCode::BAD_REQUEST)?;

            let scope = {
                let mut guard = st.oauth_refresh.lock().await;
                let Some(rec) = guard.remove(&refresh_token) else {
                    return Err(StatusCode::BAD_REQUEST);
                };
                if rec.client_id != client_id {
                    return Err(StatusCode::BAD_REQUEST);
                }
                rec.scope
            };

            // Rotate refresh tokens.
            let (access_token, new_refresh) = issue_oauth_tokens(&st, &client_id, &scope).await;
            Ok(Json(OAuthTokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: 600,
                refresh_token: Some(new_refresh),
                scope,
            }))
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn vc_issue(
    State(st): State<AppState>,
    Query(q): Query<VcIssueQuery>,
    headers: HeaderMap,
) -> Result<Json<VcIssueResponse>, StatusCode> {
    let access = extract_bearer(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    if !access.starts_with("at_") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if !is_valid_oauth_access(&st, access).await {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let now = Utc::now();
    let exp = now + chrono::Duration::days(30);
    let claims = VcClaims {
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
        iss: "agent-access-gateway".to_string(),
        sub: q.holder_did,
        scope: "quote".to_string(),
        tier: "pro".to_string(),
    };
    let vc_jwt = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&st.secret),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(VcIssueResponse {
        vc_jwt,
        expires_at_rfc3339: exp.to_rfc3339(),
    }))
}

fn expected_request_url(headers: &HeaderMap, uri: &Uri) -> Result<Url, StatusCode> {
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");

    let pq = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());
    Url::parse(&format!("{scheme}://{host}{pq}")).map_err(|_| StatusCode::BAD_REQUEST)
}

fn prune_used_dpop_jtis(used: &mut HashMap<String, i64>) {
    let now = Utc::now().timestamp();
    // Capability TTL is 10 minutes; keep DPoP JTIs a bit longer.
    let cutoff = now - (20 * 60);
    prune_and_cap_replay_cache(used, cutoff, MAX_DPOP_REPLAY_ENTRIES);
}

fn prune_used_x402_nonces(used: &mut HashMap<String, i64>) {
    let now = Utc::now().timestamp();
    // x402 authorizations are short-lived; keep a bounded replay cache.
    let cutoff = now - (60 * 60);
    prune_and_cap_replay_cache(used, cutoff, MAX_X402_NONCE_ENTRIES);
}

fn prune_and_cap_replay_cache(used: &mut HashMap<String, i64>, cutoff: i64, max_entries: usize) {
    used.retain(|_, iat| *iat >= cutoff);
    if used.len() <= max_entries {
        return;
    }

    let mut by_age = used
        .iter()
        .map(|(k, ts)| (k.clone(), *ts))
        .collect::<Vec<_>>();
    by_age.sort_by_key(|(_, ts)| *ts);
    let to_remove = used.len().saturating_sub(max_entries);
    for (k, _) in by_age.into_iter().take(to_remove) {
        let _ = used.remove(&k);
    }
}

fn prune_revoked_capabilities(revoked: &mut HashMap<String, i64>) {
    let now = Utc::now().timestamp();
    // Keep revocations for a bounded window: capabilities expire quickly (10 minutes), but we
    // retain revocations longer to be robust to clock skew and retries.
    let cutoff = now - (60 * 60);
    revoked.retain(|_, ts| *ts >= cutoff);
}

fn prune_pending_l402(pending: &mut HashMap<String, PendingL402>) {
    let cutoff = Utc::now() - chrono::Duration::minutes(10);
    pending.retain(|_, v| match v {
        PendingL402::Demo { created_at, .. } => *created_at >= cutoff,
        PendingL402::Lightning { created_at, .. } => *created_at >= cutoff,
    });
}

fn x402_v2_payment_required_for_request(
    st: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<x402_v2::PaymentRequired, StatusCode> {
    let url = expected_request_url(headers, uri)?;

    Ok(x402_v2::PaymentRequired {
        x402_version: 2,
        error: Some("PAYMENT-SIGNATURE header is required".to_string()),
        resource: x402_v2::ResourceInfo {
            url: url.to_string(),
            description: Some("Capability token for paid quote tool".to_string()),
            mime_type: Some("application/json".to_string()),
        },
        accepts: vec![x402_v2::PaymentRequirements {
            scheme: "exact".to_string(),
            network: X402_V2_NETWORK.to_string(),
            amount: st.cost_microusd.to_string(),
            asset: X402_V2_ASSET.to_string(),
            pay_to: X402_V2_PAY_TO.to_string(),
            max_timeout_seconds: X402_V2_MAX_TIMEOUT_SECONDS,
            extra: serde_json::json!({
                "assetTransferMethod": "eip3009",
                "name": X402_V2_TOKEN_NAME,
                "version": X402_V2_TOKEN_VERSION,
            }),
        }],
        extensions: serde_json::json!({}),
    })
}

async fn token(State(st): State<AppState>, uri: Uri, headers: HeaderMap) -> Response {
    // Optional DPoP binding: if a valid DPoP proof is present, bind the minted capability to the
    // proof's JWK thumbprint (cnf.jkt).
    let cnf_jkt = if let Some(dpop) = headers.get("dpop").and_then(|h| h.to_str().ok()) {
        let expected_url = match expected_request_url(&headers, &uri) {
            Ok(u) => u,
            Err(sc) => {
                return (sc, Json(serde_json::json!({"error":"invalid_request_url"})))
                    .into_response();
            }
        };

        let verified = {
            let mut used = st.used_dpop_jtis.lock().await;
            prune_used_dpop_jtis(&mut used);
            match verify_dpop_jwt(dpop, "POST", &expected_url, None, None, &mut used) {
                Ok(v) => v,
                Err(e) => {
                    if e.to_string().contains("replayed jti") {
                        return briefcase_error(
                            StatusCode::CONFLICT,
                            BRIEFCASE_ERROR_REPLAY_DETECTED,
                        );
                    }
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error":"invalid_dpop"})),
                    )
                        .into_response();
                }
            }
        };

        Some(verified.jkt)
    } else {
        // Backwards-compatible v1 PoP header: `x-briefcase-pop-pub` (Ed25519 x coordinate).
        match headers
            .get("x-briefcase-pop-pub")
            .and_then(|h| h.to_str().ok())
        {
            Some(s) if !s.is_empty() => {
                let ok = decode_b64url(s)
                    .ok()
                    .map(|v| v.len() == 32)
                    .unwrap_or(false);
                if !ok {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error":"invalid_pop_pubkey"})),
                    )
                        .into_response();
                }
                let jwk = serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": s,
                });
                match jwk_thumbprint_b64url(&jwk) {
                    Ok(jkt) => Some(jkt),
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"error":"invalid_pop_pubkey"})),
                        )
                            .into_response();
                    }
                }
            }
            _ => None,
        }
    };

    // OAuth access token path.
    if let Some(bearer) = extract_bearer(&headers)
        && bearer.starts_with("at_")
        && is_valid_oauth_access(&st, bearer).await
    {
        return (
            StatusCode::OK,
            Json(issue_capability_jwt(&st, cnf_jkt.clone())),
        )
            .into_response();
    }

    // VC entitlement path.
    if let Some(vc) = headers.get("x-vc-jwt").and_then(|h| h.to_str().ok())
        && decode_vc(&st, vc).is_ok()
    {
        return (
            StatusCode::OK,
            Json(issue_capability_jwt(&st, cnf_jkt.clone())),
        )
            .into_response();
    }

    // x402 v2 (HTTP transport): `PAYMENT-SIGNATURE` header with base64-encoded PaymentPayload.
    if let Some(sig) = headers
        .get(x402_v2::HEADER_PAYMENT_SIGNATURE)
        .and_then(|h| h.to_str().ok())
    {
        let required = match x402_v2_payment_required_for_request(&st, &headers, &uri) {
            Ok(r) => r,
            Err(sc) => {
                return (sc, Json(serde_json::json!({"error":"invalid_request_url"})))
                    .into_response();
            }
        };

        let payment_payload = match x402_v2::decode_payment_payload_b64(sig) {
            Ok(p) => p,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error":"invalid_payment_signature"})),
                )
                    .into_response();
            }
        };

        let Some(offered) = required.accepts.first() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error":"no_payment_accepts"})),
            )
                .into_response();
        };

        if &payment_payload.accepted != offered {
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({"error":"payment_terms_mismatch"})),
            )
                .into_response();
        }

        let payer = match x402_v2::evm::verify_eip3009_payload(&required, &payment_payload) {
            Ok(p) => p,
            Err(_) => {
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(serde_json::json!({"error":"payment_invalid"})),
                )
                    .into_response();
            }
        };

        // Best-effort replay protection for the demo gateway: real deployments should settle on-chain
        // (or via a facilitator) which makes the nonce authoritative.
        let scheme_payload: x402_v2::evm::ExactEvmEip3009Payload =
            match serde_json::from_value(payment_payload.payload.clone()) {
                Ok(v) => v,
                Err(_) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error":"invalid_payment_payload"})),
                    )
                        .into_response();
                }
            };

        {
            let mut used = st.used_x402_nonces.lock().await;
            prune_used_x402_nonces(&mut used);
            if used.contains_key(&scheme_payload.authorization.nonce) {
                return briefcase_error(
                    StatusCode::PAYMENT_REQUIRED,
                    BRIEFCASE_ERROR_REPLAY_DETECTED,
                );
            }
            used.insert(scheme_payload.authorization.nonce, Utc::now().timestamp());
        }

        let token = issue_capability_jwt(&st, cnf_jkt.clone());

        let mut tx = [0u8; 32];
        rand::rng().fill_bytes(&mut tx);
        let settlement = x402_v2::SettlementResponse {
            success: true,
            error_reason: None,
            payer: Some(payer),
            transaction: format!("0x{}", hex::encode(tx)),
            network: payment_payload.accepted.network,
        };
        let settlement_b64 = match x402_v2::encode_settlement_response_b64(&settlement) {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error":"payment_response_encode_failed"})),
                )
                    .into_response();
            }
        };

        let mut resp = (StatusCode::OK, Json(token)).into_response();
        if let Ok(hv) = HeaderValue::from_str(&settlement_b64) {
            resp.headers_mut()
                .insert(x402_v2::HEADER_PAYMENT_RESPONSE, hv);
        }
        return resp;
    }

    // Accept either x402 proof or l402 macaroon/preimage for the demo.
    // Preferred: Authorization schemes (more standard).
    if let Some(authz) = headers.get("authorization").and_then(|h| h.to_str().ok()) {
        if let Some(proof) = authz.strip_prefix("X402 ")
            && let Ok(tok) = issue_token_after_x402(&st, proof, cnf_jkt.as_deref()).await
        {
            return (StatusCode::OK, Json(tok)).into_response();
        };

        if let Some(rest) = authz.strip_prefix("L402 ")
            && let Some((mac, pre)) = rest.split_once(':')
            && let Ok(tok) = issue_token_after_l402(&st, mac, pre, cnf_jkt.as_deref()).await
        {
            return (StatusCode::OK, Json(tok)).into_response();
        }
    }

    // Backwards compatible headers.
    if let Some(proof) = headers.get("x-payment-proof").and_then(|h| h.to_str().ok())
        && let Ok(tok) = issue_token_after_x402(&st, proof, cnf_jkt.as_deref()).await
    {
        return (StatusCode::OK, Json(tok)).into_response();
    }

    if let (Some(mac), Some(pre)) = (
        headers.get("x-l402-macaroon").and_then(|h| h.to_str().ok()),
        headers.get("x-l402-preimage").and_then(|h| h.to_str().ok()),
    ) && let Ok(tok) = issue_token_after_l402(&st, mac, pre, cnf_jkt.as_deref()).await
    {
        return (StatusCode::OK, Json(tok)).into_response();
    }

    // No valid proof: challenge with x402 by default. If a real L402 backend is
    // configured, prefer L402 unless the client explicitly requests x402.
    let accept_rail = headers
        .get("x-accept-payment-rail")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let prefer_l402 = if accept_rail.eq_ignore_ascii_case("x402") {
        false
    } else if accept_rail.eq_ignore_ascii_case("l402") {
        true
    } else {
        st.l402_backend != L402Backend::Demo
    };

    if prefer_l402 {
        let macaroon = format!("mac_{}", Uuid::new_v4());
        let created_at = Utc::now();

        match st.l402_backend {
            L402Backend::Demo => {
                let preimage = hmac_b64url(&st.secret, macaroon.as_bytes());
                let mut guard = st.pending_l402.lock().await;
                prune_pending_l402(&mut guard);
                guard.insert(
                    macaroon.clone(),
                    PendingL402::Demo {
                        preimage,
                        created_at,
                    },
                );

                let challenge = PaymentChallenge::L402 {
                    invoice: format!("lnbc_demo_{macaroon}"),
                    macaroon,
                    amount_microusd: st.cost_microusd,
                };
                return payment_required_response(challenge);
            }
            L402Backend::Lnd => {
                #[cfg(feature = "l402-lnd")]
                {
                    let Some(lnd) = st.lnd.as_ref() else {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error":"lnd_not_configured"})),
                        )
                            .into_response();
                    };

                    let mut client = match briefcase_payments::l402_lnd::LndGrpcClient::connect(
                        briefcase_payments::l402_lnd::LndGrpcConfig {
                            endpoint: lnd.endpoint.clone(),
                            tls_cert_pem: lnd.tls_cert_pem.clone(),
                            macaroon_hex: lnd.macaroon_hex.clone(),
                            tls_domain: lnd.tls_domain.clone(),
                        },
                    )
                    .await
                    {
                        Ok(c) => c,
                        Err(_) => {
                            return (
                                StatusCode::BAD_GATEWAY,
                                Json(serde_json::json!({"error":"lnd_connect_failed"})),
                            )
                                .into_response();
                        }
                    };

                    let resp = match client
                        .add_invoice("agent-access-gateway", st.l402_invoice_sats, 600)
                        .await
                    {
                        Ok(r) => r,
                        Err(_) => {
                            return (
                                StatusCode::BAD_GATEWAY,
                                Json(serde_json::json!({"error":"lnd_add_invoice_failed"})),
                            )
                                .into_response();
                        }
                    };

                    let payment_hash_hex = hex::encode(&resp.r_hash);
                    let mut guard = st.pending_l402.lock().await;
                    prune_pending_l402(&mut guard);
                    guard.insert(
                        macaroon.clone(),
                        PendingL402::Lightning {
                            payment_hash_hex,
                            created_at,
                        },
                    );

                    let challenge = PaymentChallenge::L402 {
                        invoice: resp.payment_request,
                        macaroon,
                        amount_microusd: st.cost_microusd,
                    };
                    return payment_required_response(challenge);
                }
                #[cfg(not(feature = "l402-lnd"))]
                {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error":"l402_lnd_not_built"})),
                    )
                        .into_response();
                }
            }
            L402Backend::Cln => {
                #[cfg(all(feature = "l402-cln", unix))]
                {
                    let Some(socket) = st.cln_rpc_socket.as_ref() else {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error":"cln_not_configured"})),
                        )
                            .into_response();
                    };

                    let inv = match briefcase_payments::l402_cln::create_invoice(
                        socket,
                        (st.l402_invoice_sats as u64) * 1000,
                        &macaroon,
                        "agent-access-gateway",
                        Some(600),
                    )
                    .await
                    {
                        Ok(v) => v,
                        Err(_) => {
                            return (
                                StatusCode::BAD_GATEWAY,
                                Json(serde_json::json!({"error":"cln_invoice_failed"})),
                            )
                                .into_response();
                        }
                    };

                    let mut guard = st.pending_l402.lock().await;
                    prune_pending_l402(&mut guard);
                    guard.insert(
                        macaroon.clone(),
                        PendingL402::Lightning {
                            payment_hash_hex: inv.payment_hash_hex,
                            created_at,
                        },
                    );

                    let challenge = PaymentChallenge::L402 {
                        invoice: inv.bolt11,
                        macaroon,
                        amount_microusd: st.cost_microusd,
                    };
                    return payment_required_response(challenge);
                }
                #[cfg(any(not(feature = "l402-cln"), not(unix)))]
                {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error":"l402_cln_not_built"})),
                    )
                        .into_response();
                }
            }
        }
    }

    let payment_id = Uuid::new_v4().to_string();
    st.pending_x402
        .lock()
        .await
        .insert(payment_id.clone(), PendingPayment { paid: false });

    let challenge = PaymentChallenge::X402 {
        payment_id,
        payment_url: "/pay".to_string(),
        amount_microusd: st.cost_microusd,
    };
    let mut resp = payment_required_response(challenge);
    if let Ok(required) = x402_v2_payment_required_for_request(&st, &headers, &uri)
        && let Ok(b64) = x402_v2::encode_payment_required_b64(&required)
        && let Ok(hv) = HeaderValue::from_str(&b64)
    {
        resp.headers_mut()
            .insert(x402_v2::HEADER_PAYMENT_REQUIRED, hv);
    }
    resp
}

async fn pay(
    State(st): State<AppState>,
    Json(req): Json<PayRequest>,
) -> Result<Json<PayResponse>, StatusCode> {
    let mut guard = st.pending_x402.lock().await;
    let Some(p) = guard.get_mut(&req.payment_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    p.paid = true;
    let sig = hmac_b64url(&st.secret, req.payment_id.as_bytes());
    Ok(Json(PayResponse {
        proof: format!("{}:{}", req.payment_id, sig),
    }))
}

async fn l402_pay(
    State(st): State<AppState>,
    Json(req): Json<L402PayRequest>,
) -> Result<Json<L402PayResponse>, StatusCode> {
    if st.l402_backend != L402Backend::Demo {
        // Real L402 backends do not expose a "pay me" endpoint. The payer pays the
        // Lightning invoice directly and presents the preimage.
        return Err(StatusCode::NOT_FOUND);
    }

    // In the demo, invoice looks like `lnbc_demo_<macaroon>`.
    let macaroon = req
        .invoice
        .strip_prefix("lnbc_demo_")
        .ok_or(StatusCode::BAD_REQUEST)?;
    let guard = st.pending_l402.lock().await;
    let Some(p) = guard.get(macaroon) else {
        return Err(StatusCode::NOT_FOUND);
    };
    let PendingL402::Demo { preimage, .. } = p else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(Json(L402PayResponse {
        preimage: preimage.clone(),
    }))
}

async fn revoke(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RevokeRequest>,
) -> Response {
    // This endpoint is intended for provider-side admin usage (e.g. incident response).
    // Keep it simple: require the provider's shared secret, and only store the jti.
    let admin = match headers
        .get(HEADER_AAG_ADMIN_SECRET)
        .and_then(|h| h.to_str().ok())
    {
        Some(v) => v,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error":"missing_admin_secret"})),
            )
                .into_response();
        }
    };
    if admin.as_bytes() != st.secret.as_slice() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error":"invalid_admin_secret"})),
        )
            .into_response();
    }

    let jti = if let Some(jti) = req.jti.as_deref() {
        if jti.is_empty() || jti.len() > 128 {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid_jti"})),
            )
                .into_response();
        }
        jti.to_string()
    } else if let Some(token) = req.token.as_deref() {
        match decode_capability(&st, token) {
            Ok(claims) => claims.jti,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error":"invalid_capability_token"})),
                )
                    .into_response();
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":"missing_jti_or_token"})),
        )
            .into_response();
    };

    let now = Utc::now().timestamp();
    {
        let mut guard = st.revoked_cap_jtis.lock().await;
        prune_revoked_capabilities(&mut guard);
        guard.insert(jti.clone(), now);
    }

    (StatusCode::OK, Json(RevokeResponse { revoked: true, jti })).into_response()
}

async fn quote(
    State(st): State<AppState>,
    uri: Uri,
    Query(q): Query<QuoteQuery>,
    headers: HeaderMap,
) -> Response {
    let token = match extract_access_token(&headers) {
        Some(v) => v,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error":"missing_token"})),
            )
                .into_response();
        }
    };
    let claims = match decode_capability(&st, token) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error":"invalid_token"})),
            )
                .into_response();
        }
    };

    if claims.scope != "quote" {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"insufficient_scope"})),
        )
            .into_response();
    }

    {
        let mut guard = st.revoked_cap_jtis.lock().await;
        prune_revoked_capabilities(&mut guard);
        if guard.contains_key(&claims.jti) {
            return briefcase_error(StatusCode::FORBIDDEN, BRIEFCASE_ERROR_CAPABILITY_REVOKED);
        }
    }

    // If the capability is DPoP-bound, require a valid DPoP proof for every request.
    if let Some(cnf) = claims.cnf.as_ref() {
        let dpop = headers
            .get("dpop")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error":"missing_dpop"})),
                )
            });
        let dpop = match dpop {
            Ok(v) => v,
            Err(resp) => return resp.into_response(),
        };

        let expected_url = match expected_request_url(&headers, &uri) {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error":"invalid_request_url"})),
                )
                    .into_response();
            }
        };

        let mut used = st.used_dpop_jtis.lock().await;
        prune_used_dpop_jtis(&mut used);
        match verify_dpop_jwt(
            dpop,
            "GET",
            &expected_url,
            Some(token),
            Some(&cnf.jkt),
            &mut used,
        ) {
            Ok(_) => {}
            Err(e) => {
                if e.to_string().contains("replayed jti") {
                    return briefcase_error(StatusCode::CONFLICT, BRIEFCASE_ERROR_REPLAY_DETECTED);
                }
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error":"invalid_dpop"})),
                )
                    .into_response();
            }
        }
    }

    let mut usage = st.usage.lock().await;
    let used = usage.entry(claims.jti.clone()).or_insert(0);
    if *used >= claims.max_calls {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error":"max_calls_exceeded"})),
        )
            .into_response();
    }
    *used += 1;

    let mut rng = rand::rng();
    let price: f64 = rng.random_range(10.0..500.0);
    let ts = chrono::Utc::now().to_rfc3339();

    let mut out_headers = HeaderMap::new();
    out_headers.insert(
        "x-cost-microusd",
        st.cost_microusd.to_string().parse().unwrap(),
    );

    (
        out_headers,
        Json(serde_json::json!({
            "symbol": q.symbol.to_uppercase(),
            "price": price,
            "ts": ts
        })),
    )
        .into_response()
}

async fn issue_token_after_x402(
    st: &AppState,
    proof: &str,
    cnf_jkt: Option<&str>,
) -> anyhow::Result<TokenResponse> {
    let (payment_id, sig) = proof.split_once(':').context("invalid proof format")?;

    let expected = hmac_b64url(&st.secret, payment_id.as_bytes());
    if sig != expected {
        anyhow::bail!("bad signature");
    }

    let mut guard = st.pending_x402.lock().await;
    let Some(p) = guard.get(payment_id) else {
        anyhow::bail!("unknown payment id");
    };
    if !p.paid {
        anyhow::bail!("payment not completed");
    }
    guard.remove(payment_id);

    Ok(issue_capability_jwt(st, cnf_jkt.map(|s| s.to_string())))
}

async fn issue_token_after_l402(
    st: &AppState,
    macaroon: &str,
    preimage: &str,
    cnf_jkt: Option<&str>,
) -> anyhow::Result<TokenResponse> {
    let pending = {
        let mut guard = st.pending_l402.lock().await;
        prune_pending_l402(&mut guard);
        guard.get(macaroon).cloned().context("unknown macaroon")?
    };

    match pending {
        PendingL402::Demo { preimage: exp, .. } => {
            if exp != preimage {
                anyhow::bail!("invalid preimage");
            }
        }
        PendingL402::Lightning {
            payment_hash_hex, ..
        } => {
            let preimage_bytes = hex::decode(preimage.trim()).context("hex decode preimage")?;
            if preimage_bytes.len() != 32 {
                anyhow::bail!("preimage must be 32 bytes");
            }

            let computed = Sha256::digest(&preimage_bytes);
            if hex::encode(computed) != payment_hash_hex {
                anyhow::bail!("invalid preimage");
            }

            match st.l402_backend {
                L402Backend::Lnd => {
                    #[cfg(feature = "l402-lnd")]
                    {
                        let Some(lnd) = st.lnd.as_ref() else {
                            anyhow::bail!("lnd not configured");
                        };

                        let mut client = briefcase_payments::l402_lnd::LndGrpcClient::connect(
                            briefcase_payments::l402_lnd::LndGrpcConfig {
                                endpoint: lnd.endpoint.clone(),
                                tls_cert_pem: lnd.tls_cert_pem.clone(),
                                macaroon_hex: lnd.macaroon_hex.clone(),
                                tls_domain: lnd.tls_domain.clone(),
                            },
                        )
                        .await
                        .context("connect to lnd")?;

                        let hash = hex::decode(&payment_hash_hex).context("decode payment hash")?;
                        let inv = client
                            .lookup_invoice(&hash)
                            .await
                            .context("lookup invoice")?;

                        // LND invoice states: OPEN=0, SETTLED=1.
                        if inv.state != 1 {
                            anyhow::bail!("invoice not settled");
                        }
                    }
                    #[cfg(not(feature = "l402-lnd"))]
                    {
                        anyhow::bail!("built without l402-lnd");
                    }
                }
                L402Backend::Cln => {
                    #[cfg(all(feature = "l402-cln", unix))]
                    {
                        let Some(socket) = st.cln_rpc_socket.as_ref() else {
                            anyhow::bail!("cln not configured");
                        };

                        if !briefcase_payments::l402_cln::is_invoice_paid(socket, &payment_hash_hex)
                            .await
                            .context("cln listinvoices")?
                        {
                            anyhow::bail!("invoice not paid");
                        }
                    }
                    #[cfg(any(not(feature = "l402-cln"), not(unix)))]
                    {
                        anyhow::bail!("built without l402-cln");
                    }
                }
                L402Backend::Demo => {
                    anyhow::bail!("unexpected backend for lightning invoice");
                }
            }
        }
    }

    st.pending_l402.lock().await.remove(macaroon);
    Ok(issue_capability_jwt(st, cnf_jkt.map(|s| s.to_string())))
}

fn issue_capability_jwt(st: &AppState, cnf_jkt: Option<String>) -> TokenResponse {
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::minutes(10);
    let claims = CapabilityClaims {
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
        jti: Uuid::new_v4().to_string(),
        scope: "quote".to_string(),
        max_calls: st.max_calls,
        cost_microusd: st.cost_microusd,
        cnf: cnf_jkt.map(|jkt| CapabilityCnf { jkt }),
    };

    let token = jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&st.secret),
    )
    .expect("encode jwt");

    TokenResponse {
        token,
        expires_at_rfc3339: exp.to_rfc3339(),
        max_calls: st.max_calls,
        compatibility_profile: COMPATIBILITY_PROFILE_VERSION.to_string(),
    }
}

fn decode_capability(st: &AppState, token: &str) -> anyhow::Result<CapabilityClaims> {
    let mut validation = Validation::default();
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<CapabilityClaims>(
        token,
        &DecodingKey::from_secret(&st.secret),
        &validation,
    )?;
    Ok(data.claims)
}

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let h = headers.get("authorization")?.to_str().ok()?;
    h.strip_prefix("Bearer ")
}

fn extract_access_token(headers: &HeaderMap) -> Option<&str> {
    let h = headers.get("authorization")?.to_str().ok()?;
    if let Some(v) = h.strip_prefix("DPoP ") {
        return Some(v);
    }
    h.strip_prefix("Bearer ")
}

fn pkce_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

async fn issue_oauth_tokens(st: &AppState, client_id: &str, scope: &str) -> (String, String) {
    let access = format!("at_{}", Uuid::new_v4());
    let refresh = format!("rt_{}", Uuid::new_v4());
    let exp = Utc::now() + chrono::Duration::minutes(10);

    st.oauth_access.lock().await.insert(
        access.clone(),
        OAuthAccess {
            client_id: client_id.to_string(),
            scope: scope.to_string(),
            expires_at: exp,
        },
    );

    st.oauth_refresh.lock().await.insert(
        refresh.clone(),
        OAuthRefresh {
            client_id: client_id.to_string(),
            scope: scope.to_string(),
        },
    );

    (access, refresh)
}

async fn is_valid_oauth_access(st: &AppState, token: &str) -> bool {
    let mut guard = st.oauth_access.lock().await;
    match guard.get(token) {
        Some(rec) if Utc::now() < rec.expires_at => {
            // For the demo, access tokens are scoped to `quote` only.
            if rec.scope != "quote" {
                return false;
            }
            !rec.client_id.is_empty()
        }
        Some(_) => {
            guard.remove(token);
            false
        }
        None => false,
    }
}

fn decode_vc(st: &AppState, jwt: &str) -> anyhow::Result<VcClaims> {
    let mut validation = Validation::default();
    validation.validate_aud = false;
    let data =
        jsonwebtoken::decode::<VcClaims>(jwt, &DecodingKey::from_secret(&st.secret), &validation)?;
    Ok(data.claims)
}

fn decode_b64url(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

fn www_authenticate_for_challenge(challenge: &PaymentChallenge) -> String {
    match challenge {
        PaymentChallenge::X402 {
            payment_id,
            payment_url,
            amount_microusd,
        } => format!(
            "X402 payment_id=\"{payment_id}\", payment_url=\"{payment_url}\", amount_microusd={amount_microusd}"
        ),
        PaymentChallenge::L402 {
            invoice,
            macaroon,
            amount_microusd,
        } => format!(
            "L402 invoice=\"{invoice}\", macaroon=\"{macaroon}\", amount_microusd={amount_microusd}"
        ),
    }
}

fn payment_required_response(challenge: PaymentChallenge) -> Response {
    let www_auth = www_authenticate_for_challenge(&challenge);
    let mut resp = (StatusCode::PAYMENT_REQUIRED, Json(challenge)).into_response();
    if let Ok(hv) = HeaderValue::from_str(&www_auth) {
        resp.headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, hv);
    }
    resp
}

fn hmac_b64url(secret: &[u8], msg: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::routing::{get, post};
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn capability_docs_match_dpop_cnf_profile() {
        let docs = include_str!("../../../docs/CAPABILITY_TOKENS.md");
        assert!(docs.contains("cnf.jkt"));
        assert!(docs.contains("DPoP"));
        assert!(docs.contains("x-briefcase-pop-pub"));
    }

    #[test]
    fn replay_cache_helper_caps_entries() {
        let mut used = HashMap::new();
        for i in 0..10 {
            used.insert(format!("k{i}"), 1_000 + i);
        }
        prune_and_cap_replay_cache(&mut used, 0, 5);
        assert_eq!(used.len(), 5);
        assert!(used.values().all(|ts| *ts >= 1_005));
    }

    #[test]
    fn replay_cache_helper_drops_stale_entries_first() {
        let mut used = HashMap::new();
        for i in 0..5 {
            used.insert(format!("old{i}"), 10 + i);
        }
        for i in 0..5 {
            used.insert(format!("new{i}"), 1_000 + i);
        }
        prune_and_cap_replay_cache(&mut used, 500, 8);
        assert_eq!(used.len(), 5);
        assert!(used.keys().all(|k| k.starts_with("new")));
    }

    fn b64url(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn dpop_proof_eddsa_with(
        sk: &SigningKey,
        htu: &Url,
        method: &str,
        access_token: Option<&str>,
        iat: i64,
        jti: &str,
    ) -> String {
        let mut u = htu.clone();
        u.set_fragment(None);

        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64url(sk.verifying_key().as_bytes()),
        });
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": jwk,
        });

        let mut claims = serde_json::Map::new();
        claims.insert("htu".to_string(), serde_json::Value::String(u.to_string()));
        claims.insert(
            "htm".to_string(),
            serde_json::Value::String(method.to_uppercase()),
        );
        claims.insert("iat".to_string(), serde_json::Value::Number(iat.into()));
        claims.insert(
            "jti".to_string(),
            serde_json::Value::String(jti.to_string()),
        );
        if let Some(at) = access_token {
            claims.insert(
                "ath".to_string(),
                serde_json::Value::String(briefcase_dpop::sha256_b64url(at.as_bytes())),
            );
        }
        let payload = serde_json::Value::Object(claims);

        let header_b64 = b64url(&serde_json::to_vec(&header).expect("header json"));
        let payload_b64 = b64url(&serde_json::to_vec(&payload).expect("payload json"));
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = sk.sign(signing_input.as_bytes()).to_bytes();
        let sig_b64 = b64url(&sig);
        format!("{signing_input}.{sig_b64}")
    }

    fn dpop_proof_eddsa(
        sk: &SigningKey,
        htu: &Url,
        method: &str,
        access_token: Option<&str>,
    ) -> String {
        let iat = Utc::now().timestamp();
        let jti = Uuid::new_v4().to_string();
        dpop_proof_eddsa_with(sk, htu, method, access_token, iat, &jti)
    }

    fn dpop_proof_es256_with(
        sk: &p256::ecdsa::SigningKey,
        htu: &Url,
        method: &str,
        access_token: Option<&str>,
        iat: i64,
        jti: &str,
    ) -> String {
        let mut u = htu.clone();
        u.set_fragment(None);

        let pk = sk.verifying_key();
        let point = pk.to_encoded_point(false);
        let x = point.x().expect("p256 x");
        let y = point.y().expect("p256 y");

        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64url(x),
            "y": b64url(y),
        });
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
        });

        let mut claims = serde_json::Map::new();
        claims.insert("htu".to_string(), serde_json::Value::String(u.to_string()));
        claims.insert(
            "htm".to_string(),
            serde_json::Value::String(method.to_uppercase()),
        );
        claims.insert("iat".to_string(), serde_json::Value::Number(iat.into()));
        claims.insert(
            "jti".to_string(),
            serde_json::Value::String(jti.to_string()),
        );
        if let Some(at) = access_token {
            claims.insert(
                "ath".to_string(),
                serde_json::Value::String(briefcase_dpop::sha256_b64url(at.as_bytes())),
            );
        }
        let payload = serde_json::Value::Object(claims);

        let header_b64 = b64url(&serde_json::to_vec(&header).expect("header json"));
        let payload_b64 = b64url(&serde_json::to_vec(&payload).expect("payload json"));
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: p256::ecdsa::Signature = sk.sign(signing_input.as_bytes());
        let sig_b64 = b64url(&sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    fn dpop_proof_es256(
        sk: &p256::ecdsa::SigningKey,
        htu: &Url,
        method: &str,
        access_token: Option<&str>,
    ) -> String {
        let iat = Utc::now().timestamp();
        let jti = Uuid::new_v4().to_string();
        dpop_proof_es256_with(sk, htu, method, access_token, iat, &jti)
    }

    async fn start_test_server() -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
        let st = AppState {
            secret: b"test-secret".to_vec(),
            cost_microusd: 2000,
            max_calls: 50,
            l402_backend: L402Backend::Demo,
            l402_invoice_sats: 10,
            lnd: None,
            cln_rpc_socket: None,
            pending_x402: Arc::new(Mutex::new(HashMap::new())),
            pending_l402: Arc::new(Mutex::new(HashMap::new())),
            usage: Arc::new(Mutex::new(HashMap::new())),
            revoked_cap_jtis: Arc::new(Mutex::new(HashMap::new())),
            used_dpop_jtis: Arc::new(Mutex::new(HashMap::new())),
            used_x402_nonces: Arc::new(Mutex::new(HashMap::new())),
            oauth_codes: Arc::new(Mutex::new(HashMap::new())),
            oauth_refresh: Arc::new(Mutex::new(HashMap::new())),
            oauth_access: Arc::new(Mutex::new(HashMap::new())),
        };

        let app = Router::new()
            .route("/health", get(health))
            .route("/token", post(token))
            .route("/pay", post(pay))
            .route("/l402/pay", post(l402_pay))
            .route("/oauth/authorize", get(oauth_authorize))
            .route("/oauth/token", post(oauth_token))
            .route("/vc/issue", post(vc_issue))
            .route("/api/revoke", post(revoke))
            .route("/api/quote", get(quote))
            .layer(axum::middleware::from_fn(attach_profile_headers))
            .with_state(st);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Ok((format!("http://{addr}"), handle))
    }

    #[tokio::test]
    async fn pop_binding_requires_signature_and_prevents_replay() -> anyhow::Result<()> {
        let (base_url, handle) = start_test_server().await?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        // Generate a deterministic client keypair.
        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let token_url = Url::parse(&format!("{base_url}/token"))?;

        // Request a token: expect a 402 challenge.
        let resp = http
            .post(token_url.as_str())
            .header("DPoP", dpop_proof_eddsa(&sk, &token_url, "POST", None))
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let ch = resp.json::<PaymentChallenge>().await?;
        let PaymentChallenge::X402 {
            payment_id,
            payment_url,
            ..
        } = ch
        else {
            anyhow::bail!("expected x402 challenge");
        };

        // Pay.
        let pay_url = if payment_url.starts_with("http") {
            payment_url
        } else {
            format!("{base_url}{payment_url}")
        };
        let proof = http
            .post(pay_url)
            .json(&PayRequest { payment_id })
            .send()
            .await?
            .json::<PayResponse>()
            .await?
            .proof;

        // Token after payment: should be PoP-bound.
        let cap = http
            .post(token_url.as_str())
            .header("DPoP", dpop_proof_eddsa(&sk, &token_url, "POST", None))
            .header(reqwest::header::AUTHORIZATION, format!("X402 {proof}"))
            .send()
            .await?
            .error_for_status()?
            .json::<TokenResponse>()
            .await?
            .token;

        // Without PoP headers, quote is rejected.
        let quote_url = Url::parse(&format!("{base_url}/api/quote?symbol=TEST"))?;
        let resp = http
            .get(quote_url.as_str())
            .bearer_auth(&cap)
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // With correct DPoP proof, quote succeeds.
        let iat = Utc::now().timestamp();
        let jti = "replay1";
        let dpop = dpop_proof_eddsa_with(&sk, &quote_url, "GET", Some(&cap), iat, jti);

        let resp = http
            .get(quote_url.as_str())
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {cap}"))
            .header("DPoP", &dpop)
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        // Replay the same DPoP proof: rejected.
        let resp = http
            .get(quote_url.as_str())
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {cap}"))
            .header("DPoP", &dpop)
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            resp.headers()
                .get(HEADER_BRIEFCASE_ERROR)
                .and_then(|h| h.to_str().ok()),
            Some(BRIEFCASE_ERROR_REPLAY_DETECTED)
        );

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn pop_binding_accepts_es256_and_prevents_replay() -> anyhow::Result<()> {
        let (base_url, handle) = start_test_server().await?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        // Deterministic P-256 private key.
        let seed = [1u8; 32];
        let secret = p256::SecretKey::from_slice(&seed).expect("p256 secret");
        let sk = p256::ecdsa::SigningKey::from(secret);

        let token_url = Url::parse(&format!("{base_url}/token"))?;

        // Request a token: expect a 402 challenge.
        let resp = http
            .post(token_url.as_str())
            .header("DPoP", dpop_proof_es256(&sk, &token_url, "POST", None))
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let ch = resp.json::<PaymentChallenge>().await?;
        let PaymentChallenge::X402 {
            payment_id,
            payment_url,
            ..
        } = ch
        else {
            anyhow::bail!("expected x402 challenge");
        };

        // Pay.
        let pay_url = if payment_url.starts_with("http") {
            payment_url
        } else {
            format!("{base_url}{payment_url}")
        };
        let proof = http
            .post(pay_url)
            .json(&PayRequest { payment_id })
            .send()
            .await?
            .json::<PayResponse>()
            .await?
            .proof;

        // Token after payment: should be PoP-bound.
        let cap = http
            .post(token_url.as_str())
            .header("DPoP", dpop_proof_es256(&sk, &token_url, "POST", None))
            .header(reqwest::header::AUTHORIZATION, format!("X402 {proof}"))
            .send()
            .await?
            .error_for_status()?
            .json::<TokenResponse>()
            .await?
            .token;

        let quote_url = Url::parse(&format!("{base_url}/api/quote?symbol=TEST"))?;

        // With correct DPoP proof, quote succeeds.
        let iat = Utc::now().timestamp();
        let jti = "replay_es256_1";
        let dpop = dpop_proof_es256_with(&sk, &quote_url, "GET", Some(&cap), iat, jti);

        let resp = http
            .get(quote_url.as_str())
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {cap}"))
            .header("DPoP", &dpop)
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        // Replay the same DPoP proof: rejected.
        let resp = http
            .get(quote_url.as_str())
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {cap}"))
            .header("DPoP", &dpop)
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(
            resp.headers()
                .get(HEADER_BRIEFCASE_ERROR)
                .and_then(|h| h.to_str().ok()),
            Some(BRIEFCASE_ERROR_REPLAY_DETECTED)
        );

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn aacp_provider_advertises_compatibility_profile_header() -> anyhow::Result<()> {
        let (base_url, handle) = start_test_server().await?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let resp = http.get(format!("{base_url}/health")).send().await?;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(HEADER_BRIEFCASE_COMPATIBILITY_PROFILE)
                .and_then(|h| h.to_str().ok()),
            Some(COMPATIBILITY_PROFILE_VERSION)
        );

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn provider_contract_reference_gateway_conformance_smoke() -> anyhow::Result<()> {
        let (base_url, handle) = start_test_server().await?;
        let base = Url::parse(&base_url)?;

        let mut opts = briefcase_conformance::provider_contract::ProviderContractOptions::new(base);
        // Reference gateway in tests uses `test-secret` for both capability signing and admin ops.
        opts.admin_secret = Some(briefcase_core::Sensitive("test-secret".to_string()));
        opts.run_oauth = true;
        opts.run_revocation = true;

        let report = briefcase_conformance::provider_contract::run_provider_contract(opts).await?;
        assert!(
            report.ok,
            "provider contract report failed: {:?}",
            report.checks
        );

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn capability_jti_revoke_denies_token() -> anyhow::Result<()> {
        let (base_url, handle) = start_test_server().await?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        // Deterministic Ed25519 key.
        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let token_url = Url::parse(&format!("{base_url}/token"))?;

        // Request a token: expect a 402 challenge.
        let resp = http
            .post(token_url.as_str())
            .header("DPoP", dpop_proof_eddsa(&sk, &token_url, "POST", None))
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let ch = resp.json::<PaymentChallenge>().await?;
        let PaymentChallenge::X402 {
            payment_id,
            payment_url,
            ..
        } = ch
        else {
            anyhow::bail!("expected x402 challenge");
        };

        // Pay.
        let pay_url = if payment_url.starts_with("http") {
            payment_url
        } else {
            format!("{base_url}{payment_url}")
        };
        let proof = http
            .post(pay_url)
            .json(&PayRequest { payment_id })
            .send()
            .await?
            .json::<PayResponse>()
            .await?
            .proof;

        // Token after payment.
        let cap = http
            .post(token_url.as_str())
            .header("DPoP", dpop_proof_eddsa(&sk, &token_url, "POST", None))
            .header(reqwest::header::AUTHORIZATION, format!("X402 {proof}"))
            .send()
            .await?
            .error_for_status()?
            .json::<TokenResponse>()
            .await?
            .token;

        let mut validation = Validation::default();
        validation.validate_aud = false;
        let claims = jsonwebtoken::decode::<CapabilityClaims>(
            &cap,
            &DecodingKey::from_secret(b"test-secret"),
            &validation,
        )?
        .claims;

        // Revoke jti.
        let revoke_url = format!("{base_url}/api/revoke");
        let resp = http
            .post(revoke_url)
            .header(HEADER_AAG_ADMIN_SECRET, "test-secret")
            .json(&serde_json::json!({ "jti": claims.jti }))
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        // Quote should now be rejected with a revocation signal.
        let quote_url = Url::parse(&format!("{base_url}/api/quote?symbol=TEST"))?;
        let iat = Utc::now().timestamp();
        let dpop = dpop_proof_eddsa_with(&sk, &quote_url, "GET", Some(&cap), iat, "revoked_test");

        let resp = http
            .get(quote_url.as_str())
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {cap}"))
            .header("DPoP", &dpop)
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers()
                .get(HEADER_BRIEFCASE_ERROR)
                .and_then(|h| h.to_str().ok()),
            Some(BRIEFCASE_ERROR_CAPABILITY_REVOKED)
        );

        handle.abort();
        Ok(())
    }
}
