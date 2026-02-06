use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::debug;
use url::Url;

#[derive(Debug, Clone)]
pub struct OAuthDiscoveryResult {
    pub resource: Url,
    pub issuer: Url,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub scopes_supported: Option<Vec<String>>,
}

#[derive(Debug, Error)]
pub enum OAuthDiscoveryError {
    #[error("protected resource metadata missing authorization servers")]
    MissingAuthorizationServers,
    #[error("authorization server metadata missing issuer/authorization_endpoint/token_endpoint")]
    MissingAuthServerFields,
    #[error("invalid issuer (mismatch)")]
    IssuerMismatch,
    #[error("insecure url: {0}")]
    InsecureUrl(String),
}

#[derive(Debug, Clone, Deserialize)]
struct ProtectedResourceMetadata {
    #[serde(default)]
    authorization_servers: Vec<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthorizationServerMetadata {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
struct Cached {
    fetched_at: Instant,
    result: OAuthDiscoveryResult,
}

pub struct OAuthDiscoveryClient {
    http: reqwest::Client,
    cache: Mutex<HashMap<String, Cached>>, // key: protected resource origin
    ttl: Duration,
}

impl OAuthDiscoveryClient {
    pub fn new(ttl: Duration) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            http,
            cache: Mutex::new(HashMap::new()),
            ttl,
        })
    }

    pub async fn discover(&self, protected_resource: &Url) -> anyhow::Result<OAuthDiscoveryResult> {
        let key = origin_key(protected_resource)?;

        {
            let guard = self.cache.lock().await;
            if let Some(c) = guard.get(&key)
                && c.fetched_at.elapsed() < self.ttl
            {
                return Ok(c.result.clone());
            }
        }

        let prm_url = protected_resource_metadata_url(protected_resource)?;
        let prm = self.fetch_prm(&prm_url).await?;

        let issuer = prm
            .authorization_servers
            .first()
            .context(OAuthDiscoveryError::MissingAuthorizationServers)?
            .to_string();
        let issuer = Url::parse(&issuer).context("parse authorization server issuer")?;

        validate_https_or_loopback(&issuer).map_err(OAuthDiscoveryError::InsecureUrl)?;

        let as_meta = self.fetch_authorization_server_metadata(&issuer).await?;

        let issuer_in_doc = as_meta
            .issuer
            .as_deref()
            .context(OAuthDiscoveryError::MissingAuthServerFields)?;
        let issuer_in_doc = Url::parse(issuer_in_doc).context("parse metadata issuer")?;

        if normalize_url_str(issuer_in_doc.as_str()) != normalize_url_str(issuer.as_str()) {
            return Err(OAuthDiscoveryError::IssuerMismatch.into());
        }

        let authorization_endpoint = as_meta
            .authorization_endpoint
            .as_deref()
            .context(OAuthDiscoveryError::MissingAuthServerFields)?;
        let token_endpoint = as_meta
            .token_endpoint
            .as_deref()
            .context(OAuthDiscoveryError::MissingAuthServerFields)?;

        let authorization_endpoint =
            Url::parse(authorization_endpoint).context("parse authorization_endpoint")?;
        let token_endpoint = Url::parse(token_endpoint).context("parse token_endpoint")?;
        validate_https_or_loopback(&authorization_endpoint)
            .map_err(OAuthDiscoveryError::InsecureUrl)?;
        validate_https_or_loopback(&token_endpoint).map_err(OAuthDiscoveryError::InsecureUrl)?;

        let resource = match prm.resource {
            Some(r) => Url::parse(&r).context("parse prm.resource")?,
            None => protected_resource.clone(),
        };

        let result = OAuthDiscoveryResult {
            resource,
            issuer,
            authorization_endpoint,
            token_endpoint,
            scopes_supported: as_meta.scopes_supported.or(prm.scopes_supported),
        };

        debug!(
            protected_resource = %protected_resource,
            issuer = %result.issuer,
            "oauth discovery ok"
        );

        self.cache.lock().await.insert(
            key,
            Cached {
                fetched_at: Instant::now(),
                result: result.clone(),
            },
        );

        Ok(result)
    }

    async fn fetch_prm(&self, url: &Url) -> anyhow::Result<ProtectedResourceMetadata> {
        let resp = self
            .http
            .get(url.clone())
            .header("accept", "application/json")
            .send()
            .await
            .context("fetch protected resource metadata")?;
        if !resp.status().is_success() {
            anyhow::bail!("prm status {}", resp.status());
        }
        resp.json::<ProtectedResourceMetadata>()
            .await
            .context("decode protected resource metadata")
    }

    async fn fetch_authorization_server_metadata(
        &self,
        issuer: &Url,
    ) -> anyhow::Result<AuthorizationServerMetadata> {
        let oauth = well_known_url(issuer, ".well-known/oauth-authorization-server")?;
        let oauth_resp = self
            .http
            .get(oauth.clone())
            .header("accept", "application/json")
            .send()
            .await
            .context("fetch oauth-authorization-server metadata")?;

        if oauth_resp.status().is_success() {
            return oauth_resp
                .json::<AuthorizationServerMetadata>()
                .await
                .context("decode oauth-authorization-server metadata");
        }

        // Fall back to OIDC discovery (some deployments only publish this).
        let oidc = well_known_url(issuer, ".well-known/openid-configuration")?;
        let oidc_resp = self
            .http
            .get(oidc.clone())
            .header("accept", "application/json")
            .send()
            .await
            .context("fetch openid-configuration metadata")?;
        if !oidc_resp.status().is_success() {
            anyhow::bail!(
                "authorization server metadata not found (oauth status={}, oidc status={})",
                oauth_resp.status(),
                oidc_resp.status()
            );
        }
        oidc_resp
            .json::<AuthorizationServerMetadata>()
            .await
            .context("decode openid-configuration metadata")
    }
}

fn protected_resource_metadata_url(resource: &Url) -> anyhow::Result<Url> {
    let mut u = resource.clone();
    u.set_query(None);
    u.set_fragment(None);
    u.set_path("/.well-known/oauth-protected-resource");
    Ok(u)
}

fn well_known_url(issuer: &Url, well_known: &str) -> anyhow::Result<Url> {
    let mut u = issuer.clone();
    u.set_query(None);
    u.set_fragment(None);

    let mut path = u.path().to_string();
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(well_known.trim_start_matches('/'));
    u.set_path(&path);
    Ok(u)
}

fn normalize_url_str(raw: &str) -> String {
    raw.trim_end_matches('/').to_string()
}

fn origin_key(url: &Url) -> anyhow::Result<String> {
    let scheme = url.scheme();
    let host = url.host_str().context("url missing host")?;
    let port = url.port();
    Ok(match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

fn validate_https_or_loopback(u: &Url) -> Result<(), String> {
    match u.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = u.host().ok_or("missing host")?;
            let is_loopback = match host {
                url::Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
                url::Host::Ipv4(ip) => ip.is_loopback(),
                url::Host::Ipv6(ip) => ip.is_loopback(),
            };
            if is_loopback {
                Ok(())
            } else {
                Err("http is only allowed for localhost".to_string())
            }
        }
        s => Err(format!("unsupported scheme {s}")),
    }?;

    if !u.username().is_empty() || u.password().is_some() {
        return Err("userinfo not allowed".to_string());
    }
    if u.fragment().is_some() {
        return Err("fragment not allowed".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::extract::State;
    use axum::routing::get;
    use axum::{Json, Router};
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockState {
        port: u16,
        prm_calls: Arc<tokio::sync::Mutex<u64>>,
        meta_calls: Arc<tokio::sync::Mutex<u64>>,
    }

    async fn start_mock_server() -> anyhow::Result<(Url, MockState, tokio::task::JoinHandle<()>)> {
        async fn prm(State(st): State<MockState>) -> Json<serde_json::Value> {
            *st.prm_calls.lock().await += 1;
            Json(serde_json::json!({
                "authorization_servers": [format!("http://127.0.0.1:{}/as", st.port)],
                "resource": null,
                "scopes_supported": ["mcp.read"]
            }))
        }

        async fn meta(State(st): State<MockState>) -> Json<serde_json::Value> {
            *st.meta_calls.lock().await += 1;
            Json(serde_json::json!({
                "issuer": format!("http://127.0.0.1:{}/as", st.port),
                "authorization_endpoint": format!("http://127.0.0.1:{}/as/authorize", st.port),
                "token_endpoint": format!("http://127.0.0.1:{}/as/token", st.port),
                "scopes_supported": ["mcp.read", "mcp.write"]
            }))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let port = addr.port();

        let st = MockState {
            port,
            prm_calls: Arc::new(tokio::sync::Mutex::new(0)),
            meta_calls: Arc::new(tokio::sync::Mutex::new(0)),
        };

        let app = Router::new()
            .route("/.well-known/oauth-protected-resource", get(prm))
            .route("/as/.well-known/oauth-authorization-server", get(meta))
            .with_state(st.clone());

        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        Ok((base, st, handle))
    }

    #[tokio::test]
    async fn discovery_fetches_and_caches() -> anyhow::Result<()> {
        let (base, st, task) = start_mock_server().await?;
        let resource = base.join("/mcp").unwrap();

        let client = OAuthDiscoveryClient::new(Duration::from_secs(60))?;

        let d1 = client.discover(&resource).await?;
        assert_eq!(d1.issuer.as_str(), base.join("/as").unwrap().as_str());
        assert_eq!(
            d1.authorization_endpoint.as_str(),
            base.join("/as/authorize").unwrap().as_str()
        );
        assert_eq!(
            d1.token_endpoint.as_str(),
            base.join("/as/token").unwrap().as_str()
        );
        assert_eq!(d1.scopes_supported.unwrap().len(), 2);

        // Cached.
        let _d2 = client.discover(&resource).await?;

        let prm_calls = *st.prm_calls.lock().await;
        let meta_calls = *st.meta_calls.lock().await;
        assert_eq!(prm_calls, 1);
        assert_eq!(meta_calls, 1);

        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn normalize_url_str_trims_slashes() {
        assert_eq!(
            normalize_url_str("https://example.com/"),
            "https://example.com"
        );
        assert_eq!(
            normalize_url_str("https://example.com"),
            "https://example.com"
        );
    }
}
