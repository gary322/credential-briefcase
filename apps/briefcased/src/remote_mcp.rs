use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use briefcase_core::{
    AuthMethod, OutputFirewall, ToolCategory, ToolCost, ToolSpec, util::sha256_hex,
};
use briefcase_keys::{KeyAlgorithm, KeyHandle, SoftwareKeyManager};
use briefcase_mcp::{
    CallToolParams, HttpMcpClient, HttpMcpClientOptions, HttpRequestContext, ListToolsParams,
    PerRequestHeaderProvider,
};
use briefcase_oauth_discovery::OAuthDiscoveryClient;
use briefcase_secrets::SecretStore;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{info, warn};
use url::Url;

use crate::db::{Db, RemoteMcpServerRecord};

#[derive(Debug, Clone)]
struct RemoteToolDef {
    tool_id: String,
    remote_name: String,
    title: Option<String>,
    description: Option<String>,
    input_schema: serde_json::Value,
}

#[derive(Clone)]
struct DpopHeaderProvider {
    signer: Arc<dyn briefcase_keys::Signer>,
}

#[async_trait::async_trait]
impl PerRequestHeaderProvider for DpopHeaderProvider {
    async fn headers_for(&self, ctx: &HttpRequestContext) -> anyhow::Result<Vec<(String, String)>> {
        if !ctx.auth_scheme.eq_ignore_ascii_case("dpop") {
            return Ok(Vec::new());
        }
        let Some(tok) = ctx.auth_token.as_deref() else {
            return Ok(Vec::new());
        };
        let proof = briefcase_dpop::dpop_proof_for_resource_request(
            self.signer.as_ref(),
            &ctx.url,
            &ctx.method,
            tok,
        )
        .await?;
        Ok(vec![("DPoP".to_string(), proof)])
    }
}

struct RemoteSession {
    endpoint_url: String,
    client: HttpMcpClient,
    oauth_token_endpoint: Option<String>,
    oauth_dpop_algs: Option<Vec<String>>,
    dpop_signer: Option<Arc<dyn briefcase_keys::Signer>>,
    access_token: Option<String>,
    access_token_type: Option<String>,
    access_token_expires_at: Option<DateTime<Utc>>,
    tools: HashMap<String, RemoteToolDef>, // tool_id -> def
    fetched_at: Option<Instant>,
}

#[derive(Clone)]
pub struct RemoteMcpManager {
    db: Db,
    secrets: Arc<dyn SecretStore>,
    oauth: Arc<OAuthDiscoveryClient>,
    keys: SoftwareKeyManager,
    http: reqwest::Client,
    sessions: Arc<Mutex<HashMap<String, Arc<Mutex<RemoteSession>>>>>, // server_id -> session
    ttl: Duration,
}

impl RemoteMcpManager {
    pub fn new(
        db: Db,
        secrets: Arc<dyn SecretStore>,
        oauth: Arc<OAuthDiscoveryClient>,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build reqwest client")?;
        let keys = SoftwareKeyManager::new(secrets.clone());
        Ok(Self {
            db,
            secrets,
            oauth,
            keys,
            http,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ttl: Duration::from_secs(30),
        })
    }

    pub async fn list_tool_specs(&self) -> Vec<ToolSpec> {
        let servers = match self.db.list_remote_mcp_servers().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "list remote mcp servers failed");
                return Vec::new();
            }
        };

        let mut out = Vec::new();
        for s in servers {
            match self.refresh_server_tools(&s).await {
                Ok(defs) => out.extend(defs.into_iter().map(|d| tool_spec_for_remote(&s.id, d))),
                Err(e) => {
                    warn!(server_id = %s.id, error = %e, "remote mcp tool refresh failed");
                }
            }
        }

        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub fn is_remote_tool_id(tool_id: &str) -> bool {
        tool_id.starts_with("mcp_") && tool_id.contains("__")
    }

    pub async fn resolve_tool_spec(&self, tool_id: &str) -> anyhow::Result<Option<ToolSpec>> {
        let (server_id, _rest) = match parse_remote_tool_id(tool_id) {
            Some(v) => v,
            None => return Ok(None),
        };

        let servers = self.db.list_remote_mcp_servers().await?;
        let Some(server) = servers.into_iter().find(|s| s.id == server_id) else {
            return Ok(None);
        };

        let defs = self.refresh_server_tools(&server).await?;
        let Some(def) = defs.into_iter().find(|d| d.tool_id == tool_id) else {
            return Ok(None);
        };
        Ok(Some(tool_spec_for_remote(&server_id, def)))
    }

    pub async fn call_tool(
        &self,
        tool_id: &str,
        args: &serde_json::Value,
    ) -> anyhow::Result<(serde_json::Value, AuthMethod, Option<f64>, String)> {
        let (server_id, _rest) = parse_remote_tool_id(tool_id).context("not a remote mcp tool")?;

        let servers = self.db.list_remote_mcp_servers().await?;
        let server = servers
            .into_iter()
            .find(|s| s.id == server_id)
            .context("unknown remote mcp server id")?;

        let session = self.session_for(&server).await?;
        let mut guard = session.lock().await;

        // Endpoint changed: reset session.
        if guard.endpoint_url != server.endpoint_url {
            let endpoint =
                Url::parse(&server.endpoint_url).context("parse remote mcp endpoint_url")?;
            guard.client = HttpMcpClient::new(HttpMcpClientOptions::new(endpoint))?;
            guard.endpoint_url = server.endpoint_url.clone();
            guard.tools.clear();
            guard.fetched_at = None;
            guard.oauth_token_endpoint = None;
            guard.oauth_dpop_algs = None;
            guard.dpop_signer = None;
            guard.access_token = None;
            guard.access_token_type = None;
            guard.access_token_expires_at = None;
        }

        // If OAuth is configured for this server, ensure we have an access token attached.
        self.ensure_access_token(&server_id, &server, &mut guard)
            .await?;

        if guard
            .fetched_at
            .map(|t| t.elapsed() < self.ttl)
            .unwrap_or(false)
        {
            // ok
        } else {
            self.refresh_locked(&server_id, &server, &mut guard).await?;
        }

        let def = guard
            .tools
            .get(tool_id)
            .cloned()
            .context("remote tool not found")?;

        validate_args_against_schema(&def.input_schema, args)?;

        let res = guard
            .client
            .call_tool(CallToolParams {
                name: def.remote_name.clone(),
                arguments: Some(args.clone()),
            })
            .await?;

        // If the remote tool indicates failure, treat this as an execution error.
        if res.is_error.unwrap_or(false) {
            let msg = res
                .content
                .first()
                .map(|b| match b {
                    briefcase_mcp::ContentBlock::Text { text } => text.as_str(),
                })
                .unwrap_or("remote tool error");
            anyhow::bail!("{msg}");
        }

        let content = serde_json::json!({
            "content": res.content,
            "structuredContent": res.structured_content,
            "_meta": res.meta
        });

        Ok((
            content,
            AuthMethod::None,
            None,
            format!("remote_mcp:{server_id}"),
        ))
    }

    async fn session_for(
        &self,
        server: &RemoteMcpServerRecord,
    ) -> anyhow::Result<Arc<Mutex<RemoteSession>>> {
        let mut guard = self.sessions.lock().await;
        if let Some(s) = guard.get(&server.id) {
            return Ok(s.clone());
        }

        let endpoint = Url::parse(&server.endpoint_url).context("parse remote mcp endpoint_url")?;
        let client = HttpMcpClient::new(HttpMcpClientOptions::new(endpoint))?;

        let sess = Arc::new(Mutex::new(RemoteSession {
            endpoint_url: server.endpoint_url.clone(),
            client,
            oauth_token_endpoint: None,
            oauth_dpop_algs: None,
            dpop_signer: None,
            access_token: None,
            access_token_type: None,
            access_token_expires_at: None,
            tools: HashMap::new(),
            fetched_at: None,
        }));
        guard.insert(server.id.clone(), sess.clone());
        Ok(sess)
    }

    async fn refresh_server_tools(
        &self,
        server: &RemoteMcpServerRecord,
    ) -> anyhow::Result<Vec<RemoteToolDef>> {
        let session = self.session_for(server).await?;
        let mut guard = session.lock().await;

        // Endpoint changed: reset session.
        if guard.endpoint_url != server.endpoint_url {
            let endpoint =
                Url::parse(&server.endpoint_url).context("parse remote mcp endpoint_url")?;
            guard.client = HttpMcpClient::new(HttpMcpClientOptions::new(endpoint))?;
            guard.endpoint_url = server.endpoint_url.clone();
            guard.tools.clear();
            guard.fetched_at = None;
            guard.oauth_token_endpoint = None;
            guard.oauth_dpop_algs = None;
            guard.dpop_signer = None;
            guard.access_token = None;
            guard.access_token_type = None;
            guard.access_token_expires_at = None;
        }

        if guard
            .fetched_at
            .map(|t| t.elapsed() < self.ttl)
            .unwrap_or(false)
        {
            return Ok(guard.tools.values().cloned().collect());
        }

        self.refresh_locked(&server.id, server, &mut guard).await?;
        Ok(guard.tools.values().cloned().collect())
    }

    async fn refresh_locked(
        &self,
        server_id: &str,
        server: &RemoteMcpServerRecord,
        session: &mut RemoteSession,
    ) -> anyhow::Result<()> {
        self.ensure_access_token(server_id, server, session).await?;

        if !session.client.is_ready() {
            info!(server_id, "initializing remote mcp session");
            let _ = session
                .client
                .initialize("briefcased", env!("CARGO_PKG_VERSION"))
                .await?;
        }

        let list = session
            .client
            .list_tools(ListToolsParams::default())
            .await?;
        let mut tools = HashMap::new();
        for t in list.tools {
            let tool_id = make_remote_tool_id(server_id, &t.name);
            tools.insert(
                tool_id.clone(),
                RemoteToolDef {
                    tool_id,
                    remote_name: t.name,
                    title: t.title,
                    description: t.description,
                    input_schema: t.input_schema,
                },
            );
        }

        session.tools = tools;
        session.fetched_at = Some(Instant::now());
        Ok(())
    }

    fn select_dpop_key_algorithm(supported_algs: &[String]) -> Option<KeyAlgorithm> {
        if supported_algs
            .iter()
            .any(|a| a.eq_ignore_ascii_case("EdDSA"))
        {
            return Some(KeyAlgorithm::Ed25519);
        }
        if supported_algs
            .iter()
            .any(|a| a.eq_ignore_ascii_case("ES256"))
        {
            return Some(KeyAlgorithm::P256);
        }
        None
    }

    async fn ensure_dpop_signer(
        &self,
        server_id: &str,
        supported_algs: &[String],
    ) -> anyhow::Result<Option<Arc<dyn briefcase_keys::Signer>>> {
        let Some(want_alg) = Self::select_dpop_key_algorithm(supported_algs) else {
            return Ok(None);
        };

        let key = format!("oauth.mcp.{server_id}.dpop_key_handle");
        if let Some(raw) = self.secrets.get(&key).await? {
            let handle =
                KeyHandle::from_json(&raw.into_inner()).context("decode dpop key handle")?;
            if handle.algorithm == want_alg {
                return Ok(Some(self.keys.signer(handle)));
            }
            // Best-effort rotate mismatched key.
            let _ = self.keys.delete(&handle).await;
        }

        let handle = self.keys.generate(want_alg).await?;
        self.secrets
            .put(&key, briefcase_core::Sensitive(handle.to_json()?))
            .await?;
        Ok(Some(self.keys.signer(handle)))
    }

    async fn ensure_access_token(
        &self,
        server_id: &str,
        server: &RemoteMcpServerRecord,
        session: &mut RemoteSession,
    ) -> anyhow::Result<()> {
        // Ensure we never accidentally send a stale proof header; DPoP proofs must be per-request.
        session.client.set_header("DPoP", None);

        let key = format!("oauth.mcp.{server_id}.refresh_token");
        let Some(raw) = self.secrets.get(&key).await? else {
            session.client.set_bearer_token(None);
            session.client.set_per_request_header_provider(None);
            session.oauth_token_endpoint = None;
            session.oauth_dpop_algs = None;
            session.dpop_signer = None;
            session.access_token = None;
            session.access_token_type = None;
            session.access_token_expires_at = None;
            return Ok(());
        };
        let refresh_token =
            String::from_utf8(raw.into_inner()).context("refresh token is not utf-8")?;

        let client_id = self
            .db
            .get_remote_mcp_oauth_client(server_id)
            .await?
            .map(|r| r.client_id)
            .unwrap_or_else(|| "briefcase-cli".to_string());

        let (token_endpoint, dpop_algs) = match (
            session.oauth_token_endpoint.clone(),
            session.oauth_dpop_algs.clone(),
        ) {
            (Some(te), Some(algs)) => (te, algs),
            _ => {
                if let Some(meta) = self.db.get_remote_mcp_oauth(server_id).await? {
                    session.oauth_token_endpoint = Some(meta.token_endpoint.clone());
                    session.oauth_dpop_algs = Some(meta.dpop_signing_alg_values_supported.clone());
                    (meta.token_endpoint, meta.dpop_signing_alg_values_supported)
                } else {
                    let endpoint = Url::parse(&server.endpoint_url)
                        .context("parse remote mcp endpoint_url")?;
                    let d = self.oauth.discover(&endpoint).await?;
                    let dpop_algs = d
                        .dpop_signing_alg_values_supported
                        .clone()
                        .unwrap_or_default();
                    self.db
                        .upsert_remote_mcp_oauth(
                            server_id,
                            d.issuer.as_str(),
                            d.authorization_endpoint.as_str(),
                            d.token_endpoint.as_str(),
                            d.resource.as_str(),
                            &dpop_algs,
                        )
                        .await?;
                    session.oauth_token_endpoint = Some(d.token_endpoint.as_str().to_string());
                    session.oauth_dpop_algs = Some(dpop_algs.clone());
                    (d.token_endpoint.as_str().to_string(), dpop_algs)
                }
            }
        };

        let now = Utc::now();
        if let Some(tok) = &session.access_token
            && let Some(exp) = session.access_token_expires_at
            && now + chrono::Duration::seconds(30) < exp
        {
            let scheme = session
                .access_token_type
                .clone()
                .unwrap_or_else(|| "Bearer".to_string());
            session.client.set_auth(scheme, Some(tok.clone()));

            // Ensure the per-request DPoP proof hook is installed for DPoP tokens.
            if session
                .access_token_type
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case("dpop"))
                .unwrap_or(false)
            {
                let dpop_algs = session.oauth_dpop_algs.clone().unwrap_or_default();
                let signer = match session.dpop_signer.clone() {
                    Some(s) => s,
                    None => self
                        .ensure_dpop_signer(server_id, &dpop_algs)
                        .await?
                        .context("dpop token type but no supported dpop signer")?,
                };
                session.dpop_signer = Some(signer.clone());
                session
                    .client
                    .set_per_request_header_provider(Some(Arc::new(DpopHeaderProvider { signer })));
            } else {
                session.client.set_per_request_header_provider(None);
            }
            return Ok(());
        }

        // DPoP is optional. If the auth server supports it, use a per-server PoP key.
        let dpop_signer = self.ensure_dpop_signer(server_id, &dpop_algs).await?;

        #[derive(Debug, Deserialize)]
        struct OAuthTokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            token_type: String,
            expires_in: Option<i64>,
        }

        let mut req = self.http.post(token_endpoint.clone()).form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", client_id.as_str()),
        ]);
        if let Some(signer) = &dpop_signer {
            let token_endpoint_url =
                Url::parse(&token_endpoint).context("parse oauth token_endpoint url")?;
            let proof =
                briefcase_dpop::dpop_proof_for_token_endpoint(signer.as_ref(), &token_endpoint_url)
                    .await?;
            req = req.header("DPoP", proof);
        }

        let resp = req.send().await.context("oauth refresh request")?;
        if !resp.status().is_success() {
            anyhow::bail!("oauth refresh failed: {}", resp.status());
        }
        let tr = resp
            .json::<OAuthTokenResponse>()
            .await
            .context("decode oauth token response")?;

        let token_type = if tr.token_type.eq_ignore_ascii_case("bearer") {
            "Bearer".to_string()
        } else if tr.token_type.eq_ignore_ascii_case("dpop") {
            "DPoP".to_string()
        } else {
            tr.token_type.clone()
        };

        if let Some(new_rt) = tr.refresh_token {
            self.secrets
                .put(&key, briefcase_core::Sensitive(new_rt.into_bytes()))
                .await?;
        }

        let expires_at = now + chrono::Duration::seconds(tr.expires_in.unwrap_or(600));
        session.access_token = Some(tr.access_token.clone());
        session.access_token_type = Some(token_type.clone());
        session.access_token_expires_at = Some(expires_at);
        session
            .client
            .set_auth(token_type.clone(), Some(tr.access_token));

        session.dpop_signer = if token_type.eq_ignore_ascii_case("dpop") {
            dpop_signer
        } else {
            None
        };

        if token_type.eq_ignore_ascii_case("dpop") {
            let signer = session
                .dpop_signer
                .clone()
                .context("dpop token type but no dpop signer available")?;
            session
                .client
                .set_per_request_header_provider(Some(Arc::new(DpopHeaderProvider { signer })));
        } else {
            session.client.set_per_request_header_provider(None);
        }

        Ok(())
    }
}

fn validate_args_against_schema(
    schema: &serde_json::Value,
    args: &serde_json::Value,
) -> anyhow::Result<()> {
    let validator =
        jsonschema::validator_for(schema).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    if validator.is_valid(args) {
        return Ok(());
    }

    let msg = validator
        .iter_errors(args)
        .take(5)
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    if !msg.is_empty() {
        anyhow::bail!("{msg}");
    }
    anyhow::bail!("invalid_args");
}

fn make_remote_tool_id(server_id: &str, remote_name: &str) -> String {
    let safe_server = server_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    let safe_tool = remote_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

    if safe_server && safe_tool {
        return format!("mcp_{server_id}__{remote_name}");
    }

    // Stable fallback to avoid injecting arbitrary tool names into the gateway surface.
    let digest = sha256_hex(remote_name.as_bytes());
    format!("mcp_{server_id}__tool_{}", &digest[..12])
}

fn parse_remote_tool_id(tool_id: &str) -> Option<(String, String)> {
    let rest = tool_id.strip_prefix("mcp_")?;
    let (server_id, name) = rest.split_once("__")?;
    if server_id.is_empty() || name.is_empty() {
        return None;
    }
    Some((server_id.to_string(), name.to_string()))
}

fn tool_spec_for_remote(server_id: &str, def: RemoteToolDef) -> ToolSpec {
    ToolSpec {
        id: def.tool_id,
        name: def.title.unwrap_or_else(|| def.remote_name.clone()),
        description: def.description.unwrap_or_else(|| {
            format!(
                "Remote MCP tool `{}` from server `{}`.",
                def.remote_name, server_id
            )
        }),
        input_schema: def.input_schema,
        output_schema: serde_json::json!({"type":"object"}),
        category: ToolCategory::Other("remote".to_string()),
        cost: ToolCost::free(),
        output_firewall: OutputFirewall::allow_all(),
    }
}
