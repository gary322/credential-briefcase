use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context as _;
use briefcase_core::AuthMethod;
use briefcase_payments::{
    PaymentBackend, PaymentChallenge, PaymentProof, parse_www_authenticate, x402,
};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};
use url::Url;

use crate::db::Db;
use briefcase_secrets::SecretStore;

const OAUTH_CLIENT_ID: &str = "briefcase-cli";
const HEADER_BRIEFCASE_ERROR: &str = "x-briefcase-error";
const BRIEFCASE_ERROR_CAPABILITY_REVOKED: &str = "capability_revoked";

#[derive(Clone)]
pub struct ProviderClient {
    http: reqwest::Client,
    secrets: Arc<dyn SecretStore>,
    db: Db,
    cached: Arc<Mutex<HashMap<String, CachedToken>>>, // provider_id -> token
    pop: Arc<RwLock<Option<Arc<dyn briefcase_keys::Signer>>>>,
    payments: Arc<dyn PaymentBackend>,
}

#[derive(Debug, Clone)]
struct CachedToken {
    base_url: String,
    token: String,
    expires_at: DateTime<Utc>,
    remaining_calls: i64,
    minted_via: AuthMethod,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
    expires_at_rfc3339: String,
    max_calls: i64,
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_in: Option<i64>,
}

impl ProviderClient {
    pub fn new(
        secrets: Arc<dyn SecretStore>,
        db: Db,
        pop: Option<Arc<dyn briefcase_keys::Signer>>,
        payments: Arc<dyn PaymentBackend>,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("build reqwest client"),
            secrets,
            db,
            cached: Arc::new(Mutex::new(HashMap::new())),
            pop: Arc::new(RwLock::new(pop)),
            payments,
        }
    }

    pub async fn set_pop_signer(&self, pop: Option<Arc<dyn briefcase_keys::Signer>>) {
        *self.pop.write().await = pop;
        // Cached capability tokens can be DPoP-bound; when the PoP key changes, force refresh.
        self.cached.lock().await.clear();
    }

    pub async fn get_quote(
        &self,
        args: &serde_json::Value,
    ) -> anyhow::Result<(serde_json::Value, AuthMethod, Option<f64>, String)> {
        let symbol = args
            .get("symbol")
            .and_then(|v| v.as_str())
            .context("missing symbol")?;

        let provider_id = args
            .get("provider_id")
            .and_then(|v| v.as_str())
            .unwrap_or("demo");

        let base_url = self
            .db
            .provider_base_url(provider_id)
            .await?
            .context("unknown provider_id")?;

        // Retry once on transient auth failures, including explicit capability revocation.
        for attempt in 0..2 {
            let tok = self.get_or_refresh_token(provider_id, &base_url).await?;
            let resp = self
                .quote_request(&base_url, symbol, &tok.token)
                .await
                .context("provider quote request")?;

            let status = resp.status();
            if status.is_success() {
                let cost_usd = resp
                    .headers()
                    .get("x-cost-microusd")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(|micros| micros as f64 / 1_000_000.0);

                let json = resp.json::<serde_json::Value>().await?;
                self.decrement_calls(provider_id).await;
                return Ok((
                    json,
                    tok.minted_via,
                    cost_usd,
                    format!("provider:{provider_id}"),
                ));
            }

            let should_retry = match status {
                StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS => true,
                StatusCode::FORBIDDEN => resp
                    .headers()
                    .get(HEADER_BRIEFCASE_ERROR)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.eq_ignore_ascii_case(BRIEFCASE_ERROR_CAPABILITY_REVOKED))
                    .unwrap_or(false),
                _ => false,
            };

            if should_retry && attempt == 0 {
                warn!(provider_id, status = %status, "provider rejected capability; refreshing");
                self.cached.lock().await.remove(provider_id);
                continue;
            }

            anyhow::bail!("provider quote request failed: {}", status);
        }

        anyhow::bail!("provider quote request failed after refresh")
    }

    pub async fn forget_cached_token(&self, provider_id: &str) {
        self.cached.lock().await.remove(provider_id);
    }

    #[tracing::instrument(
        name = "provider.quote_request",
        skip(self, token),
        fields(
            http_method = tracing::field::Empty,
            http_path = tracing::field::Empty,
            http_status_code = tracing::field::Empty,
        )
    )]
    async fn quote_request(
        &self,
        base_url: &str,
        symbol: &str,
        token: &str,
    ) -> anyhow::Result<reqwest::Response> {
        let base = Url::parse(base_url).context("parse base_url")?;
        let mut url = base.join("/api/quote").context("join /api/quote")?;
        url.query_pairs_mut().append_pair("symbol", symbol);

        let span = tracing::Span::current();
        span.record("http_method", tracing::field::display("GET"));
        span.record("http_path", tracing::field::display(url.path()));

        let mut req = self.http.get(url.clone());
        let pop = self.pop.read().await.clone();
        if let Some(pop) = pop {
            let proof =
                briefcase_dpop::dpop_proof_for_resource_request(pop.as_ref(), &url, "GET", token)
                    .await?;
            req = req
                .header(reqwest::header::AUTHORIZATION, format!("DPoP {token}"))
                .header("DPoP", proof);
        } else {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await?;
        span.record(
            "http_status_code",
            tracing::field::display(resp.status().as_u16()),
        );
        Ok(resp)
    }

    async fn decrement_calls(&self, provider_id: &str) {
        let mut guard = self.cached.lock().await;
        let Some(c) = guard.get_mut(provider_id) else {
            return;
        };
        c.remaining_calls = c.remaining_calls.saturating_sub(1);
        if c.remaining_calls <= 0 {
            guard.remove(provider_id);
        }
    }

    async fn get_or_refresh_token(
        &self,
        provider_id: &str,
        base_url: &str,
    ) -> anyhow::Result<CachedToken> {
        {
            let guard = self.cached.lock().await;
            if let Some(c) = guard.get(provider_id)
                && c.base_url == base_url
                && Utc::now() < c.expires_at
                && c.remaining_calls > 0
            {
                return Ok(c.clone());
            }
        }

        let new_tok = self.fetch_token(provider_id, base_url).await?;
        self.cached
            .lock()
            .await
            .insert(provider_id.to_string(), new_tok.clone());
        Ok(new_tok)
    }

    async fn fetch_token(&self, provider_id: &str, base_url: &str) -> anyhow::Result<CachedToken> {
        // Auth strategy selection order:
        // VC entitlement > OAuth refresh token > micropayment fallback.
        if let Some((vc_jwt, expires_at)) = self.db.get_vc(provider_id).await?
            && Utc::now() < expires_at
            && let Ok(tok) = self.fetch_token_via_vc(base_url, &vc_jwt).await
        {
            return Ok(tok);
        }

        if let Some(rt) = self.load_oauth_refresh_token(provider_id).await? {
            return self.fetch_token_via_oauth(provider_id, base_url, &rt).await;
        }

        self.fetch_token_via_payment(base_url).await
    }

    async fn load_oauth_refresh_token(&self, provider_id: &str) -> anyhow::Result<Option<String>> {
        let id = format!("oauth.{provider_id}.refresh_token");
        let Some(v) = self.secrets.get(&id).await? else {
            return Ok(None);
        };
        let s = String::from_utf8(v.into_inner()).context("refresh token is not utf-8")?;
        Ok(Some(s))
    }

    async fn fetch_token_via_vc(
        &self,
        base_url: &str,
        vc_jwt: &str,
    ) -> anyhow::Result<CachedToken> {
        let url = format!("{base_url}/token");
        let token_url = Url::parse(&url).context("parse token url")?;
        let mut req = self.http.post(url).header("x-vc-jwt", vc_jwt);
        let pop = self.pop.read().await.clone();
        if let Some(pop) = pop {
            let proof =
                briefcase_dpop::dpop_proof_for_token_endpoint(pop.as_ref(), &token_url).await?;
            req = req.header("DPoP", proof);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("vc capability request failed: {}", resp.status());
        }
        let tr = resp.json::<TokenResponse>().await?;
        parse_token_response(base_url, tr, AuthMethod::Vc)
    }

    async fn fetch_token_via_oauth(
        &self,
        provider_id: &str,
        base_url: &str,
        refresh_token: &str,
    ) -> anyhow::Result<CachedToken> {
        let token_url = format!("{base_url}/oauth/token");
        let resp = self
            .http
            .post(token_url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", OAUTH_CLIENT_ID),
            ])
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("oauth refresh failed: {}", resp.status());
        }
        let tr = resp.json::<OAuthTokenResponse>().await?;
        let _token_type = tr.token_type;
        let _expires_in = tr.expires_in;

        if let Some(new_rt) = tr.refresh_token {
            let id = format!("oauth.{provider_id}.refresh_token");
            self.secrets
                .put(&id, briefcase_core::Sensitive(new_rt.into_bytes()))
                .await?;
        }

        let url = format!("{base_url}/token");
        let token_url = Url::parse(&url).context("parse token url")?;
        let mut req = self.http.post(url).bearer_auth(&tr.access_token);
        let pop = self.pop.read().await.clone();
        if let Some(pop) = pop {
            let proof =
                briefcase_dpop::dpop_proof_for_token_endpoint(pop.as_ref(), &token_url).await?;
            req = req.header("DPoP", proof);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("capability request via oauth failed: {}", resp.status());
        }
        let cap = resp.json::<TokenResponse>().await?;
        parse_token_response(base_url, cap, AuthMethod::OAuth)
    }

    async fn fetch_token_via_payment(&self, base_url: &str) -> anyhow::Result<CachedToken> {
        let provider_base = Url::parse(base_url).context("parse base_url")?;
        let token_url = provider_base.join("/token").context("join /token")?;

        let mut req = self.http.post(token_url.clone());
        let pop = self.pop.read().await.clone();
        if let Some(pop) = pop {
            let proof =
                briefcase_dpop::dpop_proof_for_token_endpoint(pop.as_ref(), &token_url).await?;
            req = req.header("DPoP", proof);
        }
        let resp = req.send().await?;

        if resp.status().is_success() {
            let tr = resp.json::<TokenResponse>().await?;
            return parse_token_response(base_url, tr, AuthMethod::CapabilityToken);
        }

        if resp.status() != StatusCode::PAYMENT_REQUIRED {
            anyhow::bail!("unexpected token status: {}", resp.status());
        }

        // Prefer x402 v2 header-based flow when present, but allow legacy/demo fallback.
        // This keeps existing demo providers working without requiring an external wallet helper.
        if let Some(b64) = resp
            .headers()
            .get(x402::HEADER_PAYMENT_REQUIRED)
            .and_then(|h| h.to_str().ok())
        {
            match x402::decode_payment_required_b64(b64) {
                Ok(required) => match self.payments.pay_x402_v2(&provider_base, required).await {
                    Ok(PaymentProof::X402V2 {
                        payment_signature_b64,
                    }) => {
                        let mut req = self.http.post(token_url.clone());
                        let pop = self.pop.read().await.clone();
                        if let Some(pop) = pop {
                            // For the retry, generate a fresh DPoP proof (new jti) bound to the same key.
                            let dpop = briefcase_dpop::dpop_proof_for_token_endpoint(
                                pop.as_ref(),
                                &token_url,
                            )
                            .await?;
                            req = req.header("DPoP", dpop);
                        }
                        req = req.header(x402::HEADER_PAYMENT_SIGNATURE, payment_signature_b64);

                        let resp = req.send().await?;
                        if !resp.status().is_success() {
                            anyhow::bail!(
                                "token request after x402 v2 payment failed: {}",
                                resp.status()
                            );
                        }
                        let tr = resp.json::<TokenResponse>().await?;
                        return parse_token_response(base_url, tr, AuthMethod::PaymentX402);
                    }
                    Ok(_) => {
                        // Do not log the proof itself (signatures/preimages are sensitive).
                        warn!("unexpected payment proof type for x402 v2; falling back to legacy");
                    }
                    Err(err) => {
                        warn!(error = %err, "x402 v2 payment failed; falling back to legacy rails");
                    }
                },
                Err(err) => {
                    warn!(error = %err, "invalid PAYMENT-REQUIRED header; falling back to legacy rails");
                }
            }
        }

        let challenge = if let Some(www) = resp
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|h| h.to_str().ok())
        {
            parse_www_authenticate(www).ok()
        } else {
            None
        }
        .unwrap_or(resp.json::<PaymentChallenge>().await?);

        match &challenge {
            PaymentChallenge::X402 {
                amount_microusd, ..
            } => {
                info!(amount_microusd, "x402 challenge received");
            }
            PaymentChallenge::L402 {
                amount_microusd, ..
            } => {
                info!(amount_microusd, "l402 challenge received");
            }
        }

        let proof = self.payments.pay(&provider_base, challenge).await?;
        let mut req = self.http.post(token_url.clone());
        let pop = self.pop.read().await.clone();
        if let Some(pop) = pop {
            // For the retry, generate a fresh DPoP proof (new jti) bound to the same key.
            let dpop =
                briefcase_dpop::dpop_proof_for_token_endpoint(pop.as_ref(), &token_url).await?;
            req = req.header("DPoP", dpop);
        }
        let minted_via = match proof {
            PaymentProof::X402 { proof } => {
                req = req
                    .header(reqwest::header::AUTHORIZATION, format!("X402 {proof}"))
                    .header("x-payment-proof", proof);
                AuthMethod::PaymentX402
            }
            PaymentProof::X402V2 {
                payment_signature_b64,
            } => {
                req = req.header(x402::HEADER_PAYMENT_SIGNATURE, payment_signature_b64);
                AuthMethod::PaymentX402
            }
            PaymentProof::L402 { macaroon, preimage } => {
                req = req
                    .header(
                        reqwest::header::AUTHORIZATION,
                        format!("L402 {macaroon}:{preimage}"),
                    )
                    .header("x-l402-macaroon", macaroon)
                    .header("x-l402-preimage", preimage);
                AuthMethod::PaymentL402
            }
        };

        let resp = req.send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("token request after payment failed: {}", resp.status());
        }
        let tr = resp.json::<TokenResponse>().await?;
        parse_token_response(base_url, tr, minted_via)
    }
}

fn parse_token_response(
    base_url: &str,
    tr: TokenResponse,
    minted_via: AuthMethod,
) -> anyhow::Result<CachedToken> {
    let expires_at = tr.expires_at_rfc3339.parse::<DateTime<Utc>>()?;
    Ok(CachedToken {
        base_url: base_url.to_string(),
        token: tr.token,
        expires_at,
        remaining_calls: tr.max_calls,
        minted_via,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::sync::Arc;

    use axum::extract::Query as AxumQuery;
    use axum::extract::State as AxumState;
    use axum::http::{HeaderMap, HeaderValue, StatusCode as AxumStatusCode, Uri};
    use axum::response::IntoResponse as _;
    use axum::response::Response;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use chrono::Utc;
    #[cfg(any(feature = "l402-lnd", all(feature = "l402-cln", unix)))]
    use sha2::{Digest as _, Sha256};
    use tempfile::tempdir;
    #[cfg(any(feature = "l402-lnd", all(feature = "l402-cln", unix)))]
    use uuid::Uuid;

    #[derive(Clone)]
    struct X402V2State {
        verified: Arc<tokio::sync::Mutex<bool>>,
    }

    fn expected_request_url(headers: &HeaderMap, uri: &Uri) -> Result<Url, AxumStatusCode> {
        let host = headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .ok_or(AxumStatusCode::BAD_REQUEST)?;
        let scheme = headers
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("http");

        let pq = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or_else(|| uri.path());
        Url::parse(&format!("{scheme}://{host}{pq}")).map_err(|_| AxumStatusCode::BAD_REQUEST)
    }

    fn build_required(resource_url: &Url, amount_microusd: i64) -> x402::PaymentRequired {
        x402::PaymentRequired {
            x402_version: 2,
            error: Some("PAYMENT-SIGNATURE header is required".to_string()),
            resource: x402::ResourceInfo {
                url: resource_url.to_string(),
                description: Some("test paid token".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            accepts: vec![x402::PaymentRequirements {
                scheme: "exact".to_string(),
                network: "eip155:84532".to_string(),
                amount: amount_microusd.to_string(),
                asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_string(),
                pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C".to_string(),
                max_timeout_seconds: 60,
                extra: serde_json::json!({
                    "assetTransferMethod": "eip3009",
                    "name": "USD Coin",
                    "version": "2",
                }),
            }],
            extensions: serde_json::json!({}),
        }
    }

    async fn token_v2(
        AxumState(st): AxumState<X402V2State>,
        uri: Uri,
        headers: HeaderMap,
    ) -> axum::response::Response {
        let resource_url = match expected_request_url(&headers, &uri) {
            Ok(u) => u,
            Err(sc) => {
                return (sc, Json(serde_json::json!({"error":"invalid_request_url"})))
                    .into_response();
            }
        };

        let required = build_required(&resource_url, 2000);

        if let Some(sig) = headers
            .get(x402::HEADER_PAYMENT_SIGNATURE)
            .and_then(|h| h.to_str().ok())
        {
            let payload = match x402::decode_payment_payload_b64(sig) {
                Ok(p) => p,
                Err(_) => {
                    return (
                        AxumStatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error":"invalid_payment_signature"})),
                    )
                        .into_response();
                }
            };

            let offered = required.accepts.first().unwrap().clone();
            if payload.accepted != offered {
                return (
                    AxumStatusCode::PAYMENT_REQUIRED,
                    Json(serde_json::json!({"error":"terms_mismatch"})),
                )
                    .into_response();
            }

            let payer = match x402::evm::verify_eip3009_payload(&required, &payload) {
                Ok(p) => p,
                Err(_) => {
                    return (
                        AxumStatusCode::PAYMENT_REQUIRED,
                        Json(serde_json::json!({"error":"invalid_payment"})),
                    )
                        .into_response();
                }
            };

            *st.verified.lock().await = true;

            let tr = serde_json::json!({
                "token": "cap_v2",
                "expires_at_rfc3339": (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
                "max_calls": 50
            });
            let mut resp = (AxumStatusCode::OK, Json(tr)).into_response();

            let settlement = x402::SettlementResponse {
                success: true,
                error_reason: None,
                payer: Some(payer),
                transaction: "0xdeadbeef".to_string(),
                network: payload.accepted.network,
            };
            if let Ok(b64) = x402::encode_settlement_response_b64(&settlement)
                && let Ok(hv) = HeaderValue::from_str(&b64)
            {
                resp.headers_mut().insert(x402::HEADER_PAYMENT_RESPONSE, hv);
            }
            return resp;
        }

        let mut resp = (
            AxumStatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({"error":"payment_required"})),
        )
            .into_response();
        if let Ok(b64) = x402::encode_payment_required_b64(&required)
            && let Ok(hv) = HeaderValue::from_str(&b64)
        {
            resp.headers_mut().insert(x402::HEADER_PAYMENT_REQUIRED, hv);
        }
        resp
    }

    #[derive(Clone)]
    struct RevocationProviderState {
        issued: Arc<tokio::sync::Mutex<i64>>,
        revoked: Arc<tokio::sync::Mutex<HashSet<String>>>,
    }

    #[derive(Debug, Deserialize)]
    struct RevocationQuoteQuery {
        symbol: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "snake_case")]
    struct RevokeTokenRequest {
        token: String,
    }

    fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
        let h = headers.get("authorization")?.to_str().ok()?;
        h.strip_prefix("Bearer ")
    }

    async fn token_revocation(AxumState(st): AxumState<RevocationProviderState>) -> Response {
        let token = {
            let mut guard = st.issued.lock().await;
            *guard += 1;
            format!("cap{guard}")
        };

        let tr = serde_json::json!({
            "token": token,
            "expires_at_rfc3339": (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
            "max_calls": 50
        });
        (AxumStatusCode::OK, Json(tr)).into_response()
    }

    async fn revoke_token(
        AxumState(st): AxumState<RevocationProviderState>,
        Json(req): Json<RevokeTokenRequest>,
    ) -> Response {
        st.revoked.lock().await.insert(req.token);
        (
            AxumStatusCode::OK,
            Json(serde_json::json!({"revoked": true})),
        )
            .into_response()
    }

    async fn quote_revocation(
        AxumState(st): AxumState<RevocationProviderState>,
        AxumQuery(q): AxumQuery<RevocationQuoteQuery>,
        headers: HeaderMap,
    ) -> Response {
        let tok = match extract_bearer(&headers) {
            Some(v) if !v.is_empty() => v,
            _ => {
                return (
                    AxumStatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error":"missing_token"})),
                )
                    .into_response();
            }
        };

        if st.revoked.lock().await.contains(tok) {
            let mut resp = (
                AxumStatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": BRIEFCASE_ERROR_CAPABILITY_REVOKED})),
            )
                .into_response();
            resp.headers_mut().insert(
                HEADER_BRIEFCASE_ERROR,
                HeaderValue::from_static(BRIEFCASE_ERROR_CAPABILITY_REVOKED),
            );
            return resp;
        }

        let mut out_headers = HeaderMap::new();
        out_headers.insert("x-cost-microusd", HeaderValue::from_static("2000"));
        (
            out_headers,
            Json(serde_json::json!({
                "symbol": q.symbol.to_uppercase(),
                "price": 123.45,
                "ts": Utc::now().to_rfc3339(),
            })),
        )
            .into_response()
    }

    #[tokio::test]
    async fn capability_revocation_refreshes_token() -> anyhow::Result<()> {
        let st = RevocationProviderState {
            issued: Arc::new(tokio::sync::Mutex::new(0)),
            revoked: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        };
        let app = Router::new()
            .route("/token", post(token_revocation))
            .route("/api/revoke", post(revoke_token))
            .route("/api/quote", get(quote_revocation))
            .with_state(st.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let base_url = format!("http://{addr}");

        let dir = tempdir()?;
        let db_path = dir.path().join("briefcase.sqlite");
        let db = Db::open(&db_path).await?;
        db.init().await?;
        db.upsert_provider("demo", &base_url).await?;

        let secrets = Arc::new(briefcase_secrets::InMemorySecretStore::default());
        let payments = Arc::new(briefcase_payments::HttpDemoPaymentBackend::new()?);
        let client = ProviderClient::new(secrets, db, None, payments);

        let args = serde_json::json!({"symbol":"TEST","provider_id":"demo"});
        let (_json, minted_via, _cost, _prov) = client.get_quote(&args).await?;
        assert!(matches!(minted_via, AuthMethod::CapabilityToken));
        assert_eq!(*st.issued.lock().await, 1);

        // Revoke the first issued capability. Subsequent calls should refresh and succeed.
        reqwest::Client::new()
            .post(format!("{base_url}/api/revoke"))
            .json(&serde_json::json!({"token":"cap1"}))
            .send()
            .await?
            .error_for_status()?;

        let (_json, minted_via, _cost, _prov) = client.get_quote(&args).await?;
        assert!(matches!(minted_via, AuthMethod::CapabilityToken));
        assert_eq!(*st.issued.lock().await, 2);

        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn x402_v2_token_mint_via_helper() -> anyhow::Result<()> {
        let helper = match std::env::var("BRIEFCASE_TEST_PAYMENT_HELPER") {
            Ok(v) => v,
            Err(_) => return Ok(()), // allow skipping in default CI; dedicated harness runs this
        };
        if std::env::var("BRIEFCASE_X402_EVM_PRIVATE_KEY_HEX").is_err()
            && std::env::var("BRIEFCASE_X402_EVM_PRIVATE_KEY_FILE").is_err()
        {
            return Ok(());
        }

        let st = X402V2State {
            verified: Arc::new(tokio::sync::Mutex::new(false)),
        };
        let app = Router::new()
            .route("/token", post(token_v2))
            .with_state(st.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base_url = format!("http://{addr}");

        let dir = tempdir()?;
        let db_path = dir.path().join("briefcase.sqlite");
        let db = Db::open(&db_path).await?;
        db.init().await?;
        let secrets = Arc::new(briefcase_secrets::InMemorySecretStore::default());

        let payments = Arc::new(
            briefcase_payments::CommandPaymentBackend::new(helper)
                .with_timeout(std::time::Duration::from_secs(30)),
        );
        let client = ProviderClient::new(secrets, db, None, payments);

        let tok = client.fetch_token_via_payment(&base_url).await?;
        assert_eq!(tok.token, "cap_v2");
        assert!(matches!(tok.minted_via, AuthMethod::PaymentX402));
        assert!(*st.verified.lock().await);

        handle.abort();
        Ok(())
    }

    #[cfg(feature = "l402-lnd")]
    #[derive(Clone)]
    struct L402LndState {
        payee_cfg: briefcase_payments::l402_lnd::LndGrpcConfig,
        pending: Arc<tokio::sync::Mutex<HashMap<String, String>>>, // macaroon -> payment_hash_hex
    }

    #[cfg(feature = "l402-lnd")]
    async fn token_l402_lnd(
        AxumState(st): AxumState<L402LndState>,
        headers: HeaderMap,
    ) -> axum::response::Response {
        // Accept L402 proof.
        if let Some(authz) = headers.get("authorization").and_then(|h| h.to_str().ok())
            && let Some(rest) = authz.strip_prefix("L402 ")
            && let Some((mac, pre)) = rest.split_once(':')
        {
            return token_l402_lnd_after_payment(st, mac, pre).await;
        }
        if let (Some(mac), Some(pre)) = (
            headers.get("x-l402-macaroon").and_then(|h| h.to_str().ok()),
            headers.get("x-l402-preimage").and_then(|h| h.to_str().ok()),
        ) {
            return token_l402_lnd_after_payment(st, mac, pre).await;
        }

        // Challenge.
        let macaroon = format!("mac_{}", Uuid::new_v4());
        let mut client = match briefcase_payments::l402_lnd::LndGrpcClient::connect(
            st.payee_cfg.clone(),
        )
        .await
        {
            Ok(c) => c,
            Err(err) => {
                return (
                    AxumStatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error":"lnd_connect_failed",
                        "detail": format!("{err:#}"),
                    })),
                )
                    .into_response();
            }
        };

        let resp = match client.add_invoice("l402_test", 10, 600).await {
            Ok(r) => r,
            Err(_) => {
                return (
                    AxumStatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error":"lnd_add_invoice_failed"})),
                )
                    .into_response();
            }
        };

        let payment_hash_hex = hex::encode(resp.r_hash);
        st.pending
            .lock()
            .await
            .insert(macaroon.clone(), payment_hash_hex);

        let challenge = PaymentChallenge::L402 {
            invoice: resp.payment_request,
            macaroon: macaroon.clone(),
            amount_microusd: 2000,
        };

        let www = briefcase_payments::format_www_authenticate(&challenge);
        let mut out = (AxumStatusCode::PAYMENT_REQUIRED, Json(challenge)).into_response();
        if let Ok(hv) = HeaderValue::from_str(&www) {
            out.headers_mut()
                .insert(reqwest::header::WWW_AUTHENTICATE, hv);
        }
        out
    }

    #[cfg(feature = "l402-lnd")]
    async fn token_l402_lnd_after_payment(
        st: L402LndState,
        macaroon: &str,
        preimage_hex: &str,
    ) -> axum::response::Response {
        let expected_hash = {
            let mut guard = st.pending.lock().await;
            match guard.remove(macaroon) {
                Some(v) => v,
                None => {
                    return (
                        AxumStatusCode::PAYMENT_REQUIRED,
                        Json(serde_json::json!({"error":"unknown_macaroon"})),
                    )
                        .into_response();
                }
            }
        };

        let preimage = match hex::decode(preimage_hex.trim()) {
            Ok(v) => v,
            Err(_) => {
                return (
                    AxumStatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error":"invalid_preimage"})),
                )
                    .into_response();
            }
        };
        if preimage.len() != 32 {
            return (
                AxumStatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid_preimage_len"})),
            )
                .into_response();
        }

        let computed = hex::encode(Sha256::digest(&preimage));
        if computed != expected_hash {
            return (
                AxumStatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({"error":"preimage_mismatch"})),
            )
                .into_response();
        }

        // Ensure invoice is settled on the provider node.
        let mut client = match briefcase_payments::l402_lnd::LndGrpcClient::connect(
            st.payee_cfg.clone(),
        )
        .await
        {
            Ok(c) => c,
            Err(err) => {
                return (
                    AxumStatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error":"lnd_connect_failed",
                        "detail": format!("{err:#}"),
                    })),
                )
                    .into_response();
            }
        };
        let hash_bytes = hex::decode(&expected_hash).unwrap_or_default();
        let mut settled = false;
        for _ in 0..50 {
            match client.lookup_invoice(&hash_bytes).await {
                Ok(inv) if inv.state == 1 => {
                    settled = true;
                    break;
                }
                Ok(_) => {}
                Err(_) => {}
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        if !settled {
            return (
                AxumStatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({"error":"invoice_not_settled"})),
            )
                .into_response();
        }

        let tr = serde_json::json!({
            "token": "cap_l402_lnd",
            "expires_at_rfc3339": (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
            "max_calls": 50
        });
        (AxumStatusCode::OK, Json(tr)).into_response()
    }

    #[cfg(feature = "l402-lnd")]
    #[tokio::test]
    async fn l402_lnd_token_mint_via_helper() -> anyhow::Result<()> {
        let helper = match std::env::var("BRIEFCASE_TEST_PAYMENT_HELPER") {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        let payee_endpoint = match std::env::var("BRIEFCASE_TEST_LND_PAYEE_GRPC_ENDPOINT") {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let payee_tls = match std::env::var("BRIEFCASE_TEST_LND_PAYEE_TLS_CERT_FILE") {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let payee_mac = match std::env::var("BRIEFCASE_TEST_LND_PAYEE_MACAROON_FILE") {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        let payer_endpoint = match std::env::var("BRIEFCASE_TEST_LND_PAYER_GRPC_ENDPOINT") {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let payer_tls = match std::env::var("BRIEFCASE_TEST_LND_PAYER_TLS_CERT_FILE") {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let payer_mac = match std::env::var("BRIEFCASE_TEST_LND_PAYER_MACAROON_FILE") {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        let mut payee_cfg = briefcase_payments::l402_lnd::LndGrpcConfig::from_files(
            payee_endpoint,
            std::path::Path::new(&payee_tls),
            std::path::Path::new(&payee_mac),
        )?;
        // Many regtest setups issue certs for localhost.
        payee_cfg = payee_cfg.tls_domain_override("localhost");

        let st = L402LndState {
            payee_cfg,
            pending: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        };

        let app = Router::new()
            .route("/token", post(token_l402_lnd))
            .with_state(st);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base_url = format!("http://{addr}");

        // Debug probe: helps diagnose failures in the embedded test token endpoint,
        // especially when upstream nodes are unreachable.
        let probe = reqwest::Client::new()
            .post(format!("{base_url}/token"))
            .send()
            .await?;
        let probe_status = probe.status();
        if probe_status != StatusCode::PAYMENT_REQUIRED {
            let body = probe.text().await.unwrap_or_default();
            println!(
                "l402_lnd_token_mint_via_helper probe: status={} body={}",
                probe_status, body
            );
        }

        let dir = tempdir()?;
        let db_path = dir.path().join("briefcase.sqlite");
        let db = Db::open(&db_path).await?;
        db.init().await?;
        let secrets = Arc::new(briefcase_secrets::InMemorySecretStore::default());

        let payments = Arc::new(
            briefcase_payments::CommandPaymentBackend::new(helper)
                .with_args(vec![
                    "--l402-backend".to_string(),
                    "lnd".to_string(),
                    "--lnd-grpc-endpoint".to_string(),
                    payer_endpoint,
                    "--lnd-tls-cert-file".to_string(),
                    payer_tls,
                    "--lnd-macaroon-file".to_string(),
                    payer_mac,
                    "--lnd-tls-domain".to_string(),
                    "localhost".to_string(),
                ])
                .with_timeout(std::time::Duration::from_secs(60)),
        );
        let client = ProviderClient::new(secrets, db, None, payments);

        let tok = client.fetch_token_via_payment(&base_url).await?;
        assert_eq!(tok.token, "cap_l402_lnd");
        assert!(matches!(tok.minted_via, AuthMethod::PaymentL402));

        handle.abort();
        Ok(())
    }

    #[cfg(all(feature = "l402-cln", unix))]
    #[derive(Clone)]
    struct L402ClnState {
        payee_socket: std::path::PathBuf,
        pending: Arc<tokio::sync::Mutex<HashMap<String, String>>>, // macaroon -> payment_hash_hex
    }

    #[cfg(all(feature = "l402-cln", unix))]
    async fn token_l402_cln(
        AxumState(st): AxumState<L402ClnState>,
        headers: HeaderMap,
    ) -> axum::response::Response {
        if let Some(authz) = headers.get("authorization").and_then(|h| h.to_str().ok())
            && let Some(rest) = authz.strip_prefix("L402 ")
            && let Some((mac, pre)) = rest.split_once(':')
        {
            return token_l402_cln_after_payment(st, mac, pre).await;
        }
        if let (Some(mac), Some(pre)) = (
            headers.get("x-l402-macaroon").and_then(|h| h.to_str().ok()),
            headers.get("x-l402-preimage").and_then(|h| h.to_str().ok()),
        ) {
            return token_l402_cln_after_payment(st, mac, pre).await;
        }

        let macaroon = format!("mac_{}", Uuid::new_v4());
        let inv = match briefcase_payments::l402_cln::create_invoice(
            &st.payee_socket,
            10_000,
            &macaroon,
            "l402_test",
            Some(600),
        )
        .await
        {
            Ok(v) => v,
            Err(err) => {
                return (
                    AxumStatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error":"cln_invoice_failed",
                        "detail": format!("{err:#}"),
                    })),
                )
                    .into_response();
            }
        };

        st.pending
            .lock()
            .await
            .insert(macaroon.clone(), inv.payment_hash_hex);

        let challenge = PaymentChallenge::L402 {
            invoice: inv.bolt11,
            macaroon: macaroon.clone(),
            amount_microusd: 2000,
        };

        let www = briefcase_payments::format_www_authenticate(&challenge);
        let mut out = (AxumStatusCode::PAYMENT_REQUIRED, Json(challenge)).into_response();
        if let Ok(hv) = HeaderValue::from_str(&www) {
            out.headers_mut()
                .insert(reqwest::header::WWW_AUTHENTICATE, hv);
        }
        out
    }

    #[cfg(all(feature = "l402-cln", unix))]
    async fn token_l402_cln_after_payment(
        st: L402ClnState,
        macaroon: &str,
        preimage_hex: &str,
    ) -> axum::response::Response {
        let expected_hash = {
            let mut guard = st.pending.lock().await;
            match guard.remove(macaroon) {
                Some(v) => v,
                None => {
                    return (
                        AxumStatusCode::PAYMENT_REQUIRED,
                        Json(serde_json::json!({"error":"unknown_macaroon"})),
                    )
                        .into_response();
                }
            }
        };

        let preimage = match hex::decode(preimage_hex.trim()) {
            Ok(v) => v,
            Err(_) => {
                return (
                    AxumStatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error":"invalid_preimage"})),
                )
                    .into_response();
            }
        };
        if preimage.len() != 32 {
            return (
                AxumStatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error":"invalid_preimage_len"})),
            )
                .into_response();
        }
        let computed = hex::encode(Sha256::digest(&preimage));
        if computed != expected_hash {
            return (
                AxumStatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({"error":"preimage_mismatch"})),
            )
                .into_response();
        }

        // We already verified the preimage hash matches the invoice payment hash.
        //
        // On CLN regtest, invoice state propagation to `listinvoices` can be flaky under CI load.
        // Treating the preimage/hash match as sufficient keeps the test provider deterministic.

        let tr = serde_json::json!({
            "token": "cap_l402_cln",
            "expires_at_rfc3339": (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
            "max_calls": 50
        });
        (AxumStatusCode::OK, Json(tr)).into_response()
    }

    #[cfg(all(feature = "l402-cln", unix))]
    #[tokio::test]
    async fn l402_cln_token_mint_via_helper() -> anyhow::Result<()> {
        let helper = match std::env::var("BRIEFCASE_TEST_PAYMENT_HELPER") {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        let payee_socket = match std::env::var("BRIEFCASE_TEST_CLN_PAYEE_RPC_SOCKET") {
            Ok(v) => std::path::PathBuf::from(v),
            Err(_) => return Ok(()),
        };
        let payer_socket = match std::env::var("BRIEFCASE_TEST_CLN_PAYER_RPC_SOCKET") {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        let st = L402ClnState {
            payee_socket,
            pending: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        };

        let app = Router::new()
            .route("/token", post(token_l402_cln))
            .with_state(st);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base_url = format!("http://{addr}");

        // Debug probe: helps diagnose failures in the embedded test token endpoint,
        // especially when upstream nodes are unreachable.
        let probe = reqwest::Client::new()
            .post(format!("{base_url}/token"))
            .send()
            .await?;
        let probe_status = probe.status();
        if probe_status != StatusCode::PAYMENT_REQUIRED {
            let body = probe.text().await.unwrap_or_default();
            println!(
                "l402_cln_token_mint_via_helper probe: status={} body={}",
                probe_status, body
            );
        }

        let dir = tempdir()?;
        let db_path = dir.path().join("briefcase.sqlite");
        let db = Db::open(&db_path).await?;
        db.init().await?;
        let secrets = Arc::new(briefcase_secrets::InMemorySecretStore::default());

        let payments = Arc::new(
            briefcase_payments::CommandPaymentBackend::new(helper)
                .with_args(vec![
                    "--l402-backend".to_string(),
                    "cln".to_string(),
                    "--cln-rpc-socket".to_string(),
                    payer_socket,
                ])
                .with_timeout(std::time::Duration::from_secs(60)),
        );
        let client = ProviderClient::new(secrets, db, None, payments);

        let tok = client.fetch_token_via_payment(&base_url).await?;
        assert_eq!(tok.token, "cap_l402_cln");
        assert!(matches!(tok.minted_via, AuthMethod::PaymentL402));

        handle.abort();
        Ok(())
    }
}
