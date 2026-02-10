use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use briefcase_core::{COMPATIBILITY_PROFILE_VERSION, Sensitive};
use briefcase_dpop::{dpop_proof_for_resource_request, dpop_proof_for_token_endpoint};
use briefcase_keys::{KeyAlgorithm, KeyBackendKind, KeyHandle, Signer};
use rand::RngCore;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;
use uuid::Uuid;

const HEADER_COMPAT_PROFILE: &str = "x-briefcase-compatibility-profile";
const HEADER_BRIEFCASE_ERROR: &str = "x-briefcase-error";
const BRIEFCASE_ERROR_REPLAY_DETECTED: &str = "replay_detected";
const BRIEFCASE_ERROR_CAPABILITY_REVOKED: &str = "capability_revoked";
const HEADER_AAG_ADMIN_SECRET: &str = "x-aag-admin-secret";

#[derive(Clone)]
pub struct ProviderContractOptions {
    pub base_url: Url,
    pub timeout: Duration,
    pub admin_secret: Option<Sensitive<String>>,
    pub run_oauth: bool,
    pub run_revocation: bool,
}

impl ProviderContractOptions {
    pub fn new(base_url: Url) -> Self {
        Self {
            base_url,
            timeout: Duration::from_secs(15),
            admin_secret: None,
            run_oauth: true,
            run_revocation: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderContractReport {
    pub base_url: String,
    pub ok: bool,
    pub checks: Vec<CheckResult>,
}

impl ProviderContractReport {
    fn new(base_url: &Url) -> Self {
        Self {
            base_url: base_url.to_string(),
            ok: true,
            checks: Vec::new(),
        }
    }

    fn push(&mut self, name: &str, ok: bool, detail: impl Into<String>) {
        self.ok &= ok;
        self.checks.push(CheckResult {
            name: name.to_string(),
            ok,
            detail: detail.into(),
        });
    }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Serialize)]
struct PayRequest {
    payment_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PayResponse {
    proof: String,
}

#[derive(Debug, Clone, Serialize)]
struct L402PayRequest {
    invoice: String,
}

#[derive(Debug, Clone, Deserialize)]
struct L402PayResponse {
    preimage: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TokenResponse {
    token: String,
    #[allow(dead_code)]
    expires_at_rfc3339: String,
    #[allow(dead_code)]
    max_calls: i64,
    #[serde(default)]
    compatibility_profile: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    token_type: String,
    expires_in: Option<i64>,
    scope: Option<String>,
}

struct InMemoryEd25519Signer {
    handle: KeyHandle,
    sk: ed25519_dalek::SigningKey,
}

impl InMemoryEd25519Signer {
    fn random() -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        Self {
            handle: KeyHandle::new(
                Uuid::new_v4().to_string(),
                KeyAlgorithm::Ed25519,
                KeyBackendKind::Software,
            ),
            sk,
        }
    }
}

#[async_trait::async_trait]
impl Signer for InMemoryEd25519Signer {
    fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    async fn public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.sk.verifying_key().as_bytes().to_vec())
    }

    async fn public_jwk(&self) -> anyhow::Result<serde_json::Value> {
        let pk = self.public_key_bytes().await?;
        Ok(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk),
        }))
    }

    async fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        use ed25519_dalek::Signer as _;
        let sig = self.sk.sign(msg).to_bytes();
        Ok(sig.to_vec())
    }
}

pub async fn run_provider_contract(
    opts: ProviderContractOptions,
) -> anyhow::Result<ProviderContractReport> {
    let client = reqwest::Client::builder()
        .timeout(opts.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build reqwest client")?;

    let mut report = ProviderContractReport::new(&opts.base_url);

    // AACP profile marker header.
    {
        let url = opts.base_url.join("/health").context("join /health")?;
        let resp = client.get(url).send().await.context("GET /health")?;
        let header = resp
            .headers()
            .get(HEADER_COMPAT_PROFILE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        report.push(
            "provider_contract_profile_marker_header",
            header == COMPATIBILITY_PROFILE_VERSION,
            format!("x-briefcase-compatibility-profile={header}"),
        );
    }

    // Payment-minted capability token should be PoP-bound when DPoP is present.
    let signer = Arc::new(InMemoryEd25519Signer::random());
    let expected_jkt = briefcase_dpop::jwk_thumbprint_b64url(&signer.public_jwk().await?)
        .context("compute jkt")?;

    let cap_resp = mint_capability_via_payment(&client, &opts.base_url, signer.clone()).await?;
    let cap_profile = cap_resp.compatibility_profile.unwrap_or_default();
    report.push(
        "provider_contract_token_response_profile_field",
        cap_profile == COMPATIBILITY_PROFILE_VERSION,
        format!("compatibility_profile={cap_profile}"),
    );
    let cap = cap_resp.token;

    {
        let claims = decode_jwt_payload(&cap).context("decode capability jwt")?;
        let got_jkt = claims
            .get("cnf")
            .and_then(|c| c.get("jkt"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        report.push(
            "provider_contract_capability_pop_binding",
            got_jkt == expected_jkt,
            "cnf.jkt present and matches DPoP key thumbprint",
        );
    }

    // Quote should reject the PoP-bound token without DPoP.
    let quote_url = quote_url(&opts.base_url, "TEST")?;
    {
        let resp = client
            .get(quote_url.clone())
            .bearer_auth(&cap)
            .send()
            .await
            .context("GET /api/quote (no DPoP)")?;
        report.push(
            "provider_contract_quote_requires_dpop_when_pop_bound",
            resp.status() == StatusCode::UNAUTHORIZED,
            format!("status={}", resp.status()),
        );
    }

    // Quote should succeed with DPoP, and replay should be rejected with a deterministic class.
    {
        let dpop = dpop_proof_for_resource_request(signer.as_ref(), &quote_url, "GET", &cap)
            .await
            .context("build dpop proof (resource)")?;

        let resp = client
            .get(quote_url.clone())
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {cap}"))
            .header("DPoP", &dpop)
            .send()
            .await
            .context("GET /api/quote (with DPoP)")?;
        report.push(
            "provider_contract_quote_accepts_dpop",
            resp.status() == StatusCode::OK,
            format!("status={}", resp.status()),
        );

        let replay = client
            .get(quote_url.clone())
            .header(reqwest::header::AUTHORIZATION, format!("DPoP {cap}"))
            .header("DPoP", &dpop)
            .send()
            .await
            .context("GET /api/quote (replay DPoP)")?;

        let got_err = replay
            .headers()
            .get(HEADER_BRIEFCASE_ERROR)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        report.push(
            "provider_contract_replay_is_deterministic_and_signaled",
            replay.status() == StatusCode::CONFLICT && got_err == BRIEFCASE_ERROR_REPLAY_DETECTED,
            format!("status={}, x-briefcase-error={got_err}", replay.status()),
        );
    }

    // OAuth code+PKCE flow should mint a capability token without payment.
    if opts.run_oauth {
        match oauth_flow_mints_capability(&client, &opts.base_url, signer.clone()).await {
            Ok(_) => report.push(
                "provider_contract_oauth_code_pkce_mints_capability",
                true,
                "ok",
            ),
            Err(e) => report.push(
                "provider_contract_oauth_code_pkce_mints_capability",
                false,
                format!("error={}", sanitize_err(&e)),
            ),
        }
    }

    // Revocation should be signaled with a stable error header when supported.
    if opts.run_revocation {
        if let Some(admin_secret) = opts.admin_secret.as_ref() {
            match revocation_is_signaled(
                &client,
                &opts.base_url,
                signer.clone(),
                &cap,
                admin_secret,
            )
            .await
            {
                Ok(_) => report.push("provider_contract_revocation_signaled", true, "ok"),
                Err(e) => report.push(
                    "provider_contract_revocation_signaled",
                    false,
                    format!("error={}", sanitize_err(&e)),
                ),
            }
        } else {
            report.push(
                "provider_contract_revocation_signaled",
                false,
                "skipped (missing admin secret)",
            );
        }
    }

    Ok(report)
}

async fn mint_capability_via_payment(
    client: &reqwest::Client,
    base_url: &Url,
    signer: Arc<dyn Signer>,
) -> anyhow::Result<TokenResponse> {
    let token_url = base_url.join("/token").context("join /token")?;

    // First attempt should challenge (unless the provider chooses a no-payment path).
    let dpop = dpop_proof_for_token_endpoint(signer.as_ref(), &token_url)
        .await
        .context("build dpop proof (token)")?;

    let resp = client
        .post(token_url.clone())
        .header("DPoP", dpop)
        .send()
        .await
        .context("POST /token (initial)")?;

    if resp.status() == StatusCode::OK {
        let tr = resp.json::<TokenResponse>().await.context("decode token")?;
        return Ok(tr);
    }

    if resp.status() != StatusCode::PAYMENT_REQUIRED {
        anyhow::bail!("unexpected token status {}", resp.status());
    }

    let ch = resp
        .json::<PaymentChallenge>()
        .await
        .context("decode payment challenge")?;

    match ch {
        PaymentChallenge::X402 {
            payment_id,
            payment_url,
            amount_microusd,
            ..
        } => {
            if amount_microusd <= 0 {
                anyhow::bail!("invalid x402 amount");
            }
            let pay_url = if payment_url.starts_with("http") {
                Url::parse(&payment_url).context("parse payment_url")?
            } else {
                base_url.join(&payment_url).context("join payment_url")?
            };
            let proof = client
                .post(pay_url)
                .json(&PayRequest { payment_id })
                .send()
                .await
                .context("POST /pay")?
                .error_for_status()
                .context("pay status")?
                .json::<PayResponse>()
                .await
                .context("decode pay response")?
                .proof;

            let dpop = dpop_proof_for_token_endpoint(signer.as_ref(), &token_url)
                .await
                .context("build dpop proof (token retry)")?;

            let tr = client
                .post(token_url)
                .header("DPoP", dpop)
                .header(reqwest::header::AUTHORIZATION, format!("X402 {proof}"))
                .send()
                .await
                .context("POST /token (x402)")?
                .error_for_status()
                .context("token status")?
                .json::<TokenResponse>()
                .await
                .context("decode token response")?;
            Ok(tr)
        }
        PaymentChallenge::L402 {
            invoice,
            macaroon,
            amount_microusd,
        } => {
            // Basic challenge sanity.
            if amount_microusd <= 0 {
                anyhow::bail!("invalid l402 amount");
            }
            if invoice.trim().is_empty() || macaroon.trim().is_empty() {
                anyhow::bail!("invalid l402 challenge");
            }
            // Reference gateway helper endpoint (demo only).
            let pay_url = base_url.join("/l402/pay").context("join /l402/pay")?;
            let preimage = client
                .post(pay_url)
                .json(&L402PayRequest { invoice })
                .send()
                .await
                .context("POST /l402/pay")?
                .error_for_status()
                .context("l402 pay status")?
                .json::<L402PayResponse>()
                .await
                .context("decode l402 pay response")?
                .preimage;

            let dpop = dpop_proof_for_token_endpoint(signer.as_ref(), &token_url)
                .await
                .context("build dpop proof (token retry)")?;

            let tr = client
                .post(token_url)
                .header("DPoP", dpop)
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("L402 {macaroon}:{preimage}"),
                )
                .send()
                .await
                .context("POST /token (l402)")?
                .error_for_status()
                .context("token status")?
                .json::<TokenResponse>()
                .await
                .context("decode token response")?;
            Ok(tr)
        }
    }
}

async fn oauth_flow_mints_capability(
    client: &reqwest::Client,
    base_url: &Url,
    signer: Arc<dyn Signer>,
) -> anyhow::Result<()> {
    let client_id = "briefcase-conformance";
    let redirect_uri = "http://127.0.0.1/callback";

    let code_verifier = random_token_b64url(32);
    let code_challenge = pkce_s256(&code_verifier);

    let mut authorize = base_url
        .join("/oauth/authorize")
        .context("join /oauth/authorize")?;
    {
        let mut qp = authorize.query_pairs_mut();
        qp.append_pair("response_type", "code");
        qp.append_pair("client_id", client_id);
        qp.append_pair("redirect_uri", redirect_uri);
        qp.append_pair("scope", "quote");
        qp.append_pair("code_challenge", &code_challenge);
        qp.append_pair("code_challenge_method", "S256");
        qp.append_pair("state", "state");
    }

    let resp = client
        .get(authorize)
        .send()
        .await
        .context("GET /oauth/authorize")?;
    if !resp.status().is_redirection() {
        anyhow::bail!("unexpected authorize status {}", resp.status());
    }
    let loc = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|h| h.to_str().ok())
        .context("missing location")?;
    let loc = Url::parse(loc).context("parse location")?;
    let code = loc
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .context("missing code")?;

    let token_url = base_url.join("/oauth/token").context("join /oauth/token")?;
    let oauth = client
        .post(token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", code_verifier.as_str()),
        ])
        .send()
        .await
        .context("POST /oauth/token")?
        .error_for_status()
        .context("oauth token status")?
        .json::<OAuthTokenResponse>()
        .await
        .context("decode oauth token")?;

    if !oauth.token_type.eq_ignore_ascii_case("bearer") {
        anyhow::bail!("unexpected token_type");
    }
    if oauth.expires_in.unwrap_or(0) <= 0 {
        anyhow::bail!("unexpected expires_in");
    }
    if let Some(scope) = oauth.scope.as_deref()
        && !scope.is_empty()
        && scope != "quote"
    {
        anyhow::bail!("unexpected oauth scope");
    }

    // Mint capability via OAuth access token.
    let cap_url = base_url.join("/token").context("join /token")?;
    let dpop = dpop_proof_for_token_endpoint(signer.as_ref(), &cap_url)
        .await
        .context("build dpop proof (cap via oauth)")?;
    let resp = client
        .post(cap_url)
        .header("DPoP", dpop)
        .bearer_auth(&oauth.access_token)
        .send()
        .await
        .context("POST /token (oauth)")?;

    if resp.status() != StatusCode::OK {
        anyhow::bail!("capability via oauth status {}", resp.status());
    }
    let tr = resp.json::<TokenResponse>().await.context("decode token")?;

    // Basic claim sanity (no signature verification).
    let claims = decode_jwt_payload(&tr.token).context("decode capability jwt")?;
    let scope = claims.get("scope").and_then(|v| v.as_str()).unwrap_or("");
    if scope != "quote" {
        anyhow::bail!("unexpected scope");
    }

    // Refresh token flow (if advertised).
    if let Some(rt) = oauth.refresh_token.as_deref() {
        let token_url = base_url.join("/oauth/token").context("join /oauth/token")?;
        let refreshed = client
            .post(token_url)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", rt),
                ("client_id", client_id),
            ])
            .send()
            .await
            .context("POST /oauth/token (refresh)")?
            .error_for_status()
            .context("oauth refresh status")?
            .json::<OAuthTokenResponse>()
            .await
            .context("decode oauth refresh token")?;
        if refreshed.access_token.trim().is_empty() {
            anyhow::bail!("refresh flow missing access_token");
        }
        if refreshed.refresh_token.as_deref().unwrap_or("").is_empty() {
            anyhow::bail!("refresh flow missing refresh_token");
        }
    }

    Ok(())
}

async fn revocation_is_signaled(
    client: &reqwest::Client,
    base_url: &Url,
    signer: Arc<dyn Signer>,
    cap: &str,
    admin_secret: &Sensitive<String>,
) -> anyhow::Result<()> {
    let claims = decode_jwt_payload(cap).context("decode capability jwt")?;
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .context("missing jti")?;

    let revoke_url = base_url.join("/api/revoke").context("join /api/revoke")?;
    let resp = client
        .post(revoke_url)
        .header(HEADER_AAG_ADMIN_SECRET, admin_secret.0.as_str())
        .json(&serde_json::json!({ "jti": jti }))
        .send()
        .await
        .context("POST /api/revoke")?;
    if resp.status() != StatusCode::OK {
        anyhow::bail!("revoke status {}", resp.status());
    }

    let quote_url = quote_url(base_url, "TEST")?;
    let dpop = dpop_proof_for_resource_request(signer.as_ref(), &quote_url, "GET", cap)
        .await
        .context("build dpop proof (revoked)")?;
    let resp = client
        .get(quote_url)
        .header(reqwest::header::AUTHORIZATION, format!("DPoP {cap}"))
        .header("DPoP", dpop)
        .send()
        .await
        .context("GET /api/quote (revoked)")?;
    if resp.status() != StatusCode::FORBIDDEN {
        anyhow::bail!("revoked status {}", resp.status());
    }
    let err = resp
        .headers()
        .get(HEADER_BRIEFCASE_ERROR)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if err != BRIEFCASE_ERROR_CAPABILITY_REVOKED {
        anyhow::bail!("missing revocation error header");
    }
    Ok(())
}

fn quote_url(base_url: &Url, symbol: &str) -> anyhow::Result<Url> {
    let mut u = base_url.join("/api/quote").context("join /api/quote")?;
    u.query_pairs_mut().append_pair("symbol", symbol);
    Ok(u)
}

fn decode_jwt_payload(jwt: &str) -> anyhow::Result<serde_json::Value> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("invalid jwt");
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .context("b64 decode payload")?;
    serde_json::from_slice(&payload_bytes).context("parse jwt payload json")
}

fn pkce_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn random_token_b64url(nbytes: usize) -> String {
    let mut bytes = vec![0u8; nbytes];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn sanitize_err(e: &anyhow::Error) -> String {
    // Avoid emitting multi-line errors into reports.
    let mut s = e.to_string().replace('\n', " ");
    if s.len() > 200 {
        s.truncate(200);
    }
    s
}
