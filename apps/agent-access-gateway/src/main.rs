use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse as _, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use clap::Parser;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use hmac::{Hmac, Mac};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;
use tracing::info;
use url::Url;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

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
}

#[derive(Clone)]
struct AppState {
    secret: Vec<u8>,
    cost_microusd: i64,
    max_calls: i64,
    pending_x402: Arc<Mutex<HashMap<String, PendingPayment>>>,
    pending_l402: Arc<Mutex<HashMap<String, PendingL402>>>,
    usage: Arc<Mutex<HashMap<String, i64>>>, // jti -> calls
    used_nonces: Arc<Mutex<HashMap<String, DateTime<Utc>>>>, // `${jti}:${nonce}` -> ts
    oauth_codes: Arc<Mutex<HashMap<String, OAuthCode>>>, // code -> record
    oauth_refresh: Arc<Mutex<HashMap<String, OAuthRefresh>>>, // refresh -> record
    oauth_access: Arc<Mutex<HashMap<String, OAuthAccess>>>, // access -> record
}

#[derive(Debug, Clone)]
struct PendingPayment {
    paid: bool,
}

#[derive(Debug, Clone)]
struct PendingL402 {
    preimage: String,
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
    /// If set, requests must include a PoP signature verified against this Ed25519 public key.
    pop_pk_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QuoteQuery {
    symbol: String,
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
    let st = AppState {
        secret: args.secret.as_bytes().to_vec(),
        cost_microusd: args.cost_microusd,
        max_calls: args.max_calls,
        pending_x402: Arc::new(Mutex::new(HashMap::new())),
        pending_l402: Arc::new(Mutex::new(HashMap::new())),
        usage: Arc::new(Mutex::new(HashMap::new())),
        used_nonces: Arc::new(Mutex::new(HashMap::new())),
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
        .route("/api/quote", get(quote))
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

async fn token(State(st): State<AppState>, headers: HeaderMap) -> Response {
    // Optional PoP pubkey binding (Ed25519 public key, base64url-no-pad).
    let pop_pk_b64 = match headers
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
            Some(s.to_string())
        }
        _ => None,
    };

    // OAuth access token path.
    if let Some(bearer) = extract_bearer(&headers)
        && bearer.starts_with("at_")
        && is_valid_oauth_access(&st, bearer).await
    {
        return (
            StatusCode::OK,
            Json(issue_capability_jwt(&st, pop_pk_b64.clone())),
        )
            .into_response();
    }

    // VC entitlement path.
    if let Some(vc) = headers.get("x-vc-jwt").and_then(|h| h.to_str().ok())
        && decode_vc(&st, vc).is_ok()
    {
        return (
            StatusCode::OK,
            Json(issue_capability_jwt(&st, pop_pk_b64.clone())),
        )
            .into_response();
    }

    // Accept either x402 proof or l402 macaroon/preimage for the demo.
    // Preferred: Authorization schemes (more standard).
    if let Some(authz) = headers.get("authorization").and_then(|h| h.to_str().ok()) {
        if let Some(proof) = authz.strip_prefix("X402 ")
            && let Ok(tok) = issue_token_after_x402(&st, proof, pop_pk_b64.as_deref()).await
        {
            return (StatusCode::OK, Json(tok)).into_response();
        };

        if let Some(rest) = authz.strip_prefix("L402 ")
            && let Some((mac, pre)) = rest.split_once(':')
            && let Ok(tok) = issue_token_after_l402(&st, mac, pre, pop_pk_b64.as_deref()).await
        {
            return (StatusCode::OK, Json(tok)).into_response();
        }
    }

    // Backwards compatible headers.
    if let Some(proof) = headers.get("x-payment-proof").and_then(|h| h.to_str().ok())
        && let Ok(tok) = issue_token_after_x402(&st, proof, pop_pk_b64.as_deref()).await
    {
        return (StatusCode::OK, Json(tok)).into_response();
    }

    if let (Some(mac), Some(pre)) = (
        headers.get("x-l402-macaroon").and_then(|h| h.to_str().ok()),
        headers.get("x-l402-preimage").and_then(|h| h.to_str().ok()),
    ) && let Ok(tok) = issue_token_after_l402(&st, mac, pre, pop_pk_b64.as_deref()).await
    {
        return (StatusCode::OK, Json(tok)).into_response();
    }

    // No valid proof: challenge with x402 by default. Clients can request l402 via header.
    let prefer_l402 = headers
        .get("x-accept-payment-rail")
        .and_then(|h| h.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("l402"))
        .unwrap_or(false);

    if prefer_l402 {
        let macaroon = format!("mac_{}", Uuid::new_v4());
        let preimage = hmac_b64url(&st.secret, macaroon.as_bytes());
        st.pending_l402
            .lock()
            .await
            .insert(macaroon.clone(), PendingL402 { preimage });

        let challenge = PaymentChallenge::L402 {
            invoice: format!("lnbc_demo_{macaroon}"),
            macaroon,
            amount_microusd: st.cost_microusd,
        };
        return payment_required_response(challenge);
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
    payment_required_response(challenge)
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
    // In the demo, invoice looks like `lnbc_demo_<macaroon>`.
    let macaroon = req
        .invoice
        .strip_prefix("lnbc_demo_")
        .ok_or(StatusCode::BAD_REQUEST)?;
    let guard = st.pending_l402.lock().await;
    let Some(p) = guard.get(macaroon) else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(Json(L402PayResponse {
        preimage: p.preimage.clone(),
    }))
}

async fn quote(
    State(st): State<AppState>,
    uri: Uri,
    Query(q): Query<QuoteQuery>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<serde_json::Value>), StatusCode> {
    let token = extract_bearer(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let claims = decode_capability(&st, token).map_err(|_| StatusCode::UNAUTHORIZED)?;

    if claims.scope != "quote" {
        return Err(StatusCode::FORBIDDEN);
    }

    // If the capability is PoP-bound, require a DPoP-like signature for every request.
    if let Some(pk_b64) = claims.pop_pk_b64.as_deref() {
        verify_pop_request(&st, pk_b64, token, &uri, &headers).await?;
    }

    let mut usage = st.usage.lock().await;
    let used = usage.entry(claims.jti.clone()).or_insert(0);
    if *used >= claims.max_calls {
        return Err(StatusCode::TOO_MANY_REQUESTS);
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

    Ok((
        out_headers,
        Json(serde_json::json!({
            "symbol": q.symbol.to_uppercase(),
            "price": price,
            "ts": ts
        })),
    ))
}

async fn issue_token_after_x402(
    st: &AppState,
    proof: &str,
    pop_pk_b64: Option<&str>,
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

    Ok(issue_capability_jwt(st, pop_pk_b64.map(|s| s.to_string())))
}

async fn issue_token_after_l402(
    st: &AppState,
    macaroon: &str,
    preimage: &str,
    pop_pk_b64: Option<&str>,
) -> anyhow::Result<TokenResponse> {
    let mut guard = st.pending_l402.lock().await;
    let Some(p) = guard.get(macaroon) else {
        anyhow::bail!("unknown macaroon");
    };
    if p.preimage != preimage {
        anyhow::bail!("invalid preimage");
    }
    guard.remove(macaroon);
    Ok(issue_capability_jwt(st, pop_pk_b64.map(|s| s.to_string())))
}

fn issue_capability_jwt(st: &AppState, pop_pk_b64: Option<String>) -> TokenResponse {
    let now = chrono::Utc::now();
    let exp = now + chrono::Duration::minutes(10);
    let claims = CapabilityClaims {
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
        jti: Uuid::new_v4().to_string(),
        scope: "quote".to_string(),
        max_calls: st.max_calls,
        cost_microusd: st.cost_microusd,
        pop_pk_b64,
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

fn sha256_b64url(msg: &[u8]) -> String {
    let digest = Sha256::digest(msg);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
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

async fn verify_pop_request(
    st: &AppState,
    pk_b64: &str,
    token: &str,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
    let ver = headers
        .get("x-briefcase-pop-ver")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if ver != "1" {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let ts_s = headers
        .get("x-briefcase-pop-ts")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let ts: i64 = ts_s.parse().map_err(|_| StatusCode::UNAUTHORIZED)?;

    let now = Utc::now().timestamp();
    const MAX_SKEW_SECS: i64 = 120;
    if (now - ts).abs() > MAX_SKEW_SECS {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let nonce = headers
        .get("x-briefcase-pop-nonce")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if nonce.is_empty() || nonce.len() > 128 {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let sig_b64 = headers
        .get("x-briefcase-pop-sig")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let pk_bytes: [u8; 32] = decode_b64url(pk_b64)
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .try_into()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let sig_bytes: [u8; 64] = decode_b64url(sig_b64)
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .try_into()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let sig = Signature::from_bytes(&sig_bytes);

    let token_hash_b64 = sha256_b64url(token.as_bytes());
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());

    // Signature message:
    // `v1\n<method>\n<path?query>\n<ts>\n<nonce>\n<sha256_b64url(capability_jwt)>`
    let msg = format!("v1\nGET\n{path_and_query}\n{ts_s}\n{nonce}\n{token_hash_b64}");
    vk.verify(msg.as_bytes(), &sig)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Replay defense: `${token_hash}:${nonce}` must be unique.
    let key = format!("{token_hash_b64}:{nonce}");
    let now_dt = Utc::now();
    {
        let mut guard = st.used_nonces.lock().await;

        // Opportunistic pruning. Capability TTL is 10 minutes; keep a bit longer.
        let cutoff = now_dt - chrono::Duration::minutes(20);
        guard.retain(|_, seen_at| *seen_at > cutoff);

        if guard.contains_key(&key) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        guard.insert(key, now_dt);
    }

    Ok(())
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

    async fn start_test_server() -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
        let st = AppState {
            secret: b"test-secret".to_vec(),
            cost_microusd: 2000,
            max_calls: 50,
            pending_x402: Arc::new(Mutex::new(HashMap::new())),
            pending_l402: Arc::new(Mutex::new(HashMap::new())),
            usage: Arc::new(Mutex::new(HashMap::new())),
            used_nonces: Arc::new(Mutex::new(HashMap::new())),
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
            .route("/api/quote", get(quote))
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
        let pk_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.verifying_key().as_bytes());

        // Request a token: expect a 402 challenge.
        let resp = http
            .post(format!("{base_url}/token"))
            .header("x-briefcase-pop-pub", &pk_b64)
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
            .post(format!("{base_url}/token"))
            .header("x-briefcase-pop-pub", &pk_b64)
            .header(reqwest::header::AUTHORIZATION, format!("X402 {proof}"))
            .send()
            .await?
            .error_for_status()?
            .json::<TokenResponse>()
            .await?
            .token;

        // Without PoP headers, quote is rejected.
        let resp = http
            .get(format!("{base_url}/api/quote?symbol=TEST"))
            .bearer_auth(&cap)
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // With correct PoP headers, quote succeeds.
        let ts = Utc::now().timestamp().to_string();
        let nonce = "nonce123".to_string();
        let token_hash_b64 = sha256_b64url(cap.as_bytes());
        let msg = format!("v1\nGET\n/api/quote?symbol=TEST\n{ts}\n{nonce}\n{token_hash_b64}");
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sk.sign(msg.as_bytes()).to_bytes());

        let resp = http
            .get(format!("{base_url}/api/quote?symbol=TEST"))
            .bearer_auth(&cap)
            .header("x-briefcase-pop-ver", "1")
            .header("x-briefcase-pop-ts", &ts)
            .header("x-briefcase-pop-nonce", &nonce)
            .header("x-briefcase-pop-sig", &sig_b64)
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::OK);

        // Replay the same nonce: rejected.
        let resp = http
            .get(format!("{base_url}/api/quote?symbol=TEST"))
            .bearer_auth(&cap)
            .header("x-briefcase-pop-ver", "1")
            .header("x-briefcase-pop-ts", &ts)
            .header("x-briefcase-pop-nonce", &nonce)
            .header("x-briefcase-pop-sig", &sig_b64)
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        handle.abort();
        Ok(())
    }
}
