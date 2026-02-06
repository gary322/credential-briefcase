use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context as _;
use briefcase_core::AuthMethod;
use briefcase_payments::{PaymentBackend, PaymentChallenge, PaymentProof, parse_www_authenticate};
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{info, warn};
use url::Url;

use crate::db::Db;
use briefcase_secrets::SecretStore;

const OAUTH_CLIENT_ID: &str = "briefcase-cli";

#[derive(Clone)]
pub struct ProviderClient {
    http: reqwest::Client,
    secrets: Arc<dyn SecretStore>,
    db: Db,
    cached: Arc<Mutex<HashMap<String, CachedToken>>>, // provider_id -> token
    pop: Option<Arc<dyn briefcase_keys::Signer>>,
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
            pop,
            payments,
        }
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

        let tok = self.get_or_refresh_token(provider_id, &base_url).await?;

        let resp = self
            .quote_request(&base_url, symbol, &tok.token)
            .await
            .context("provider quote request")?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            warn!(provider_id, "provider rejected cached token; refreshing");
            self.cached.lock().await.remove(provider_id);
            let tok = self.get_or_refresh_token(provider_id, &base_url).await?;
            return self
                .get_quote_with_token(
                    provider_id,
                    &base_url,
                    symbol,
                    &tok.token,
                    tok.minted_via.clone(),
                )
                .await;
        }

        let cost_usd = resp
            .headers()
            .get("x-cost-microusd")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .map(|micros| micros as f64 / 1_000_000.0);

        let json = resp.json::<serde_json::Value>().await?;
        self.decrement_calls(provider_id).await;
        Ok((
            json,
            tok.minted_via,
            cost_usd,
            format!("provider:{provider_id}"),
        ))
    }

    async fn get_quote_with_token(
        &self,
        provider_id: &str,
        base_url: &str,
        symbol: &str,
        token: &str,
        minted_via: AuthMethod,
    ) -> anyhow::Result<(serde_json::Value, AuthMethod, Option<f64>, String)> {
        let resp = self
            .quote_request(base_url, symbol, token)
            .await
            .context("provider quote request (retry)")?;

        let cost_usd = resp
            .headers()
            .get("x-cost-microusd")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .map(|micros| micros as f64 / 1_000_000.0);

        let json = resp.json::<serde_json::Value>().await?;
        self.decrement_calls(provider_id).await;
        Ok((
            json,
            minted_via,
            cost_usd,
            format!("provider:{provider_id}"),
        ))
    }

    async fn quote_request(
        &self,
        base_url: &str,
        symbol: &str,
        token: &str,
    ) -> anyhow::Result<reqwest::Response> {
        let base = Url::parse(base_url).context("parse base_url")?;
        let mut url = base.join("/api/quote").context("join /api/quote")?;
        url.query_pairs_mut().append_pair("symbol", symbol);

        let mut req = self.http.get(url.clone());
        if let Some(pop) = &self.pop {
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
        // Auth strategy selection order (per sop.txt):
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
        if let Some(pop) = &self.pop {
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
        if let Some(pop) = &self.pop {
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
        if let Some(pop) = &self.pop {
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
        if let Some(pop) = &self.pop {
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
