use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use briefcase_core::{
    AuthMethod, OutputFirewall, ToolCategory, ToolCost, ToolSpec, util::sha256_hex,
};
use briefcase_mcp::{CallToolParams, HttpMcpClient, HttpMcpClientOptions, ListToolsParams};
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

struct RemoteSession {
    endpoint_url: String,
    client: HttpMcpClient,
    tools: HashMap<String, RemoteToolDef>, // tool_id -> def
    fetched_at: Option<Instant>,
}

#[derive(Clone)]
pub struct RemoteMcpManager {
    db: Db,
    sessions: Arc<Mutex<HashMap<String, Arc<Mutex<RemoteSession>>>>>, // server_id -> session
    ttl: Duration,
}

impl RemoteMcpManager {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            ttl: Duration::from_secs(30),
        }
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
        _server: &RemoteMcpServerRecord,
        session: &mut RemoteSession,
    ) -> anyhow::Result<()> {
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
