use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use briefcase_core::{
    AuthMethod, OutputFirewallMode, ToolCategory, ToolCost, ToolRuntimeKind, ToolSpec,
};
use briefcase_sandbox::{
    DeterministicHttpHandler, HttpHandler, SandboxLimits, SandboxPolicy, WasmSandbox,
};
use jsonschema::Validator;
use thiserror::Error;
use url::Url;

use crate::db::Db;
use crate::provider::ProviderClient;

#[derive(Clone)]
pub struct ToolRegistry {
    tools: HashMap<String, Arc<ToolRuntime>>,
}

impl ToolRegistry {
    pub fn new(provider: ProviderClient, db: Db) -> Self {
        let mut tools = HashMap::new();
        let provider = Arc::new(provider);
        let quote_sandbox = Arc::new(
            WasmSandbox::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/forward_http_request.wasm"
            )))
            .expect("compile quote wasm tool"),
        );
        let fs_read_sandbox = Arc::new(
            WasmSandbox::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/forward_fs_read.wasm"
            )))
            .expect("compile fs_read wasm tool"),
        );

        tools.insert(
            "echo".to_string(),
            Arc::new(ToolRuntime::new(tool_echo_spec(), ToolImpl::Echo).expect("valid schema")),
        );

        tools.insert(
            "quote".to_string(),
            Arc::new(
                ToolRuntime::new(
                    tool_quote_spec(),
                    ToolImpl::QuoteSandbox {
                        provider,
                        db: db.clone(),
                        sandbox: quote_sandbox,
                    },
                )
                .expect("valid schema"),
            ),
        );

        tools.insert(
            "note_add".to_string(),
            Arc::new(
                ToolRuntime::new(tool_note_add_spec(), ToolImpl::NoteAdd { db: db.clone() })
                    .expect("valid schema"),
            ),
        );

        tools.insert(
            "file_read".to_string(),
            Arc::new(
                ToolRuntime::new(
                    tool_file_read_spec(),
                    ToolImpl::FileReadSandbox {
                        db: db.clone(),
                        sandbox: fs_read_sandbox,
                    },
                )
                .expect("valid schema"),
            ),
        );

        tools.insert(
            "notes_list".to_string(),
            Arc::new(
                ToolRuntime::new(
                    tool_notes_list_spec(),
                    ToolImpl::NotesList { db: db.clone() },
                )
                .expect("valid schema"),
            ),
        );

        Self { tools }
    }

    pub fn get(&self, id: &str) -> Option<Arc<ToolRuntime>> {
        self.tools.get(id).cloned()
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        let mut v = self
            .tools
            .values()
            .map(|t| t.spec.clone())
            .collect::<Vec<_>>();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }
}

pub struct ToolRuntime {
    pub spec: ToolSpec,
    validator: Validator,
    imp: ToolImpl,
}

enum ToolImpl {
    Echo,
    QuoteSandbox {
        provider: Arc<ProviderClient>,
        db: Db,
        sandbox: Arc<WasmSandbox>,
    },
    FileReadSandbox {
        db: Db,
        sandbox: Arc<WasmSandbox>,
    },
    NoteAdd {
        db: Db,
    },
    NotesList {
        db: Db,
    },
}

#[derive(Debug, Error)]
pub enum ToolRuntimeError {
    #[error("execution error: {0}")]
    Exec(String),

    #[error("sandbox_violation:{0}")]
    SandboxViolation(String),
}

impl ToolRuntime {
    fn new(spec: ToolSpec, imp: ToolImpl) -> anyhow::Result<Self> {
        let validator = jsonschema::validator_for(&spec.input_schema)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(Self {
            spec,
            validator,
            imp,
        })
    }

    pub fn validate_args(&self, args: &serde_json::Value) -> anyhow::Result<()> {
        if self.validator.is_valid(args) {
            return Ok(());
        }

        let msg = self
            .validator
            .iter_errors(args)
            .take(5)
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        if !msg.is_empty() {
            anyhow::bail!("{msg}");
        }

        // Fallback (should not happen): invalid but no errors returned.
        anyhow::bail!("invalid_args");
    }

    pub async fn execute(
        &self,
        args: &serde_json::Value,
    ) -> Result<(serde_json::Value, AuthMethod, Option<f64>, String), ToolRuntimeError> {
        match &self.imp {
            ToolImpl::Echo => {
                let text = args
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                Ok((
                    serde_json::json!({ "echo": text }),
                    AuthMethod::None,
                    Some(self.spec.cost.estimated_usd),
                    "local:echo".to_string(),
                ))
            }
            ToolImpl::QuoteSandbox {
                provider,
                db,
                sandbox,
            } => {
                let manifest = db
                    .get_tool_manifest(&self.spec.id)
                    .await
                    .map_err(|e| ToolRuntimeError::Exec(e.to_string()))?
                    .unwrap_or_else(|| {
                        briefcase_core::ToolManifest::deny_all(
                            self.spec.id.clone(),
                            ToolRuntimeKind::Wasm,
                        )
                    });

                let policy = SandboxPolicy::allow_hosts(manifest.egress.allowed_hosts.clone());
                let mut limits = SandboxLimits::default();
                limits.max_output_bytes = usize::try_from(manifest.limits.max_output_bytes)
                    .unwrap_or(usize::MAX)
                    .min(4 * 1024 * 1024);

                let expected_args = args.clone();
                let meta = Arc::new(std::sync::Mutex::new(None::<QuoteSandboxMeta>));
                let handler = Arc::new(QuoteSandboxHttpHandler {
                    tokio: tokio::runtime::Handle::current(),
                    provider: provider.clone(),
                    db: db.clone(),
                    policy: policy.clone(),
                    allowed_http_path_prefixes: manifest.egress.allowed_http_path_prefixes.clone(),
                    expected_args,
                    meta: meta.clone(),
                });

                let input = serde_json::to_string(args)
                    .map_err(|e| ToolRuntimeError::Exec(e.to_string()))?;

                let sandbox = sandbox.clone();
                let out = tokio::task::spawn_blocking(move || {
                    sandbox.execute(&policy, &limits, handler, &input)
                })
                .await
                .map_err(|e| ToolRuntimeError::Exec(e.to_string()))?
                .map_err(|e| {
                    let msg = format!("{e:#}");
                    if msg.contains("sandbox violation")
                        || msg.contains("egress denied")
                        || msg.contains("response too large")
                        || msg.contains("out of bounds")
                        || msg.contains("fuel")
                    {
                        ToolRuntimeError::SandboxViolation(msg)
                    } else {
                        ToolRuntimeError::Exec(msg)
                    }
                })?;

                let content: serde_json::Value = serde_json::from_str(&out)
                    .map_err(|e| ToolRuntimeError::Exec(e.to_string()))?;

                let meta = meta.lock().expect("meta poisoned").clone().ok_or_else(|| {
                    ToolRuntimeError::Exec("sandbox_missing_provenance".to_string())
                })?;

                Ok((content, meta.auth_method, meta.cost_usd, meta.source))
            }
            ToolImpl::FileReadSandbox { db, sandbox } => {
                let manifest = db
                    .get_tool_manifest(&self.spec.id)
                    .await
                    .map_err(|e| ToolRuntimeError::Exec(e.to_string()))?
                    .unwrap_or_else(|| {
                        briefcase_core::ToolManifest::deny_all(
                            self.spec.id.clone(),
                            ToolRuntimeKind::Wasm,
                        )
                    });

                let policy = SandboxPolicy::allow_hosts(manifest.egress.allowed_hosts.clone())
                    .with_fs_paths(
                        manifest
                            .filesystem
                            .allowed_path_prefixes
                            .into_iter()
                            .map(PathBuf::from),
                    );

                let mut limits = SandboxLimits::default();
                limits.max_output_bytes = usize::try_from(manifest.limits.max_output_bytes)
                    .unwrap_or(usize::MAX)
                    .min(4 * 1024 * 1024);

                let path = args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("missing path")
                    .map_err(|e| ToolRuntimeError::Exec(e.to_string()))?;

                let sandbox = sandbox.clone();
                let input = path.to_string();
                let out = tokio::task::spawn_blocking(move || {
                    sandbox.execute(&policy, &limits, Arc::new(DeterministicHttpHandler), &input)
                })
                .await
                .map_err(|e| ToolRuntimeError::Exec(e.to_string()))?
                .map_err(|e| {
                    let msg = format!("{e:#}");
                    if msg.contains("fs denied") || msg.contains("sandbox violation") {
                        ToolRuntimeError::SandboxViolation(msg)
                    } else {
                        ToolRuntimeError::Exec(msg)
                    }
                })?;

                let content: serde_json::Value = serde_json::from_str(&out)
                    .map_err(|e| ToolRuntimeError::Exec(e.to_string()))?;

                Ok((
                    content,
                    AuthMethod::None,
                    Some(self.spec.cost.estimated_usd),
                    "local:file_read".to_string(),
                ))
            }
            ToolImpl::NoteAdd { db } => {
                let text = args
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                let id = db
                    .add_note(text)
                    .await
                    .map_err(|e| ToolRuntimeError::Exec(e.to_string()))?;
                Ok((
                    serde_json::json!({ "note_id": id }),
                    AuthMethod::None,
                    Some(self.spec.cost.estimated_usd),
                    "local:notes".to_string(),
                ))
            }
            ToolImpl::NotesList { db } => {
                let ids = db
                    .list_note_ids(50)
                    .await
                    .map_err(|e| ToolRuntimeError::Exec(e.to_string()))?;
                Ok((
                    serde_json::json!({ "note_ids": ids }),
                    AuthMethod::None,
                    Some(self.spec.cost.estimated_usd),
                    "local:notes".to_string(),
                ))
            }
        }
    }

    pub fn apply_output_firewall(&self, value: serde_json::Value) -> serde_json::Value {
        crate::firewall::apply_output_firewall(&self.spec.output_firewall, value)
    }
}

#[derive(Debug, Clone)]
struct QuoteSandboxMeta {
    auth_method: AuthMethod,
    cost_usd: Option<f64>,
    source: String,
}

#[derive(Clone)]
struct QuoteSandboxHttpHandler {
    tokio: tokio::runtime::Handle,
    provider: Arc<ProviderClient>,
    db: Db,
    policy: SandboxPolicy,
    allowed_http_path_prefixes: Vec<String>,
    expected_args: serde_json::Value,
    meta: Arc<std::sync::Mutex<Option<QuoteSandboxMeta>>>,
}

impl HttpHandler for QuoteSandboxHttpHandler {
    fn handle(&self, request_json: &str) -> anyhow::Result<String> {
        // This tool is intentionally strict: the wasm module isn't allowed to mutate the
        // validated args before requesting an outbound connector call.
        let v: serde_json::Value =
            serde_json::from_str(request_json).context("parse request as json")?;
        if v != self.expected_args {
            anyhow::bail!("sandbox violation: args mismatch");
        }

        let provider_id = v
            .get("provider_id")
            .and_then(|x| x.as_str())
            .unwrap_or("demo");

        let base_url = self
            .tokio
            .block_on(self.db.provider_base_url(provider_id))?
            .context("unknown provider_id")?;

        let parsed = Url::parse(&base_url).context("parse provider base_url")?;
        if !self.policy.allows_url(&parsed) {
            anyhow::bail!("sandbox violation: egress denied");
        }

        // Quote uses a fixed safe path. We still enforce an explicit allowlist to avoid
        // accidentally allowing tools to hit token endpoints and exfiltrate responses.
        let quote_path = "/api/quote";
        if !self
            .allowed_http_path_prefixes
            .iter()
            .any(|p| quote_path.starts_with(p))
        {
            anyhow::bail!("sandbox violation: http path denied");
        }

        let (content, auth_method, cost_usd, source) =
            self.tokio.block_on(self.provider.get_quote(&v))?;

        *self.meta.lock().expect("meta poisoned") = Some(QuoteSandboxMeta {
            auth_method,
            cost_usd,
            source,
        });

        serde_json::to_string(&content).context("encode provider json")
    }
}

fn tool_file_read_spec() -> ToolSpec {
    ToolSpec {
        id: "file_read".to_string(),
        name: "File Read".to_string(),
        description: "Reads a file from an allowlisted path prefix. This is a write-category tool and requires approval by default.".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "minLength": 1, "maxLength": 4096 }
            },
            "required": ["path"],
            "additionalProperties": false
        }),
        output_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "ok": { "type": "boolean" },
                "bytes": { "type": "integer" },
                "data_b64": { "type": "string" }
            },
            "required": ["ok"],
            "additionalProperties": true
        }),
        category: ToolCategory::Write,
        cost: ToolCost::free(),
        output_firewall: briefcase_core::OutputFirewall {
            mode: OutputFirewallMode::AllowPaths,
            allowed_paths: vec![
                "ok".to_string(),
                "bytes".to_string(),
                "data_b64".to_string(),
            ],
        },
    }
}

fn tool_echo_spec() -> ToolSpec {
    ToolSpec {
        id: "echo".to_string(),
        name: "Echo".to_string(),
        description: "Returns the provided text.".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "text": { "type": "string", "maxLength": 4096 }
            },
            "required": ["text"],
            "additionalProperties": false
        }),
        output_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "echo": { "type": "string" }
            },
            "required": ["echo"],
            "additionalProperties": false
        }),
        category: ToolCategory::Read,
        cost: ToolCost::free(),
        output_firewall: briefcase_core::OutputFirewall::allow_all(),
    }
}

fn tool_quote_spec() -> ToolSpec {
    ToolSpec {
        id: "quote".to_string(),
        name: "Quote".to_string(),
        description: "Gets a market quote from a provider gateway (default provider_id=demo)."
            .to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "provider_id": { "type": "string", "minLength": 1, "maxLength": 64 },
                "symbol": { "type": "string", "minLength": 1, "maxLength": 16 }
            },
            "required": ["symbol"],
            "additionalProperties": false
        }),
        output_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "symbol": { "type": "string" },
                "price": { "type": "number" },
                "ts": { "type": "string" }
            },
            "required": ["symbol", "price", "ts"],
            "additionalProperties": true
        }),
        category: ToolCategory::Read,
        cost: ToolCost {
            estimated_usd: 0.002,
        },
        output_firewall: briefcase_core::OutputFirewall {
            mode: OutputFirewallMode::AllowPaths,
            allowed_paths: vec!["symbol".to_string(), "price".to_string(), "ts".to_string()],
        },
    }
}

fn tool_note_add_spec() -> ToolSpec {
    ToolSpec {
        id: "note_add".to_string(),
        name: "Note Add".to_string(),
        description: "Stores a local note. This is a write tool and requires approval by default."
            .to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "text": { "type": "string", "minLength": 1, "maxLength": 4096 }
            },
            "required": ["text"],
            "additionalProperties": false
        }),
        output_schema: serde_json::json!({
            "type": "object",
            "properties": { "note_id": { "type": "integer" } },
            "required": ["note_id"],
            "additionalProperties": false
        }),
        category: ToolCategory::Write,
        cost: ToolCost::free(),
        output_firewall: briefcase_core::OutputFirewall::allow_all(),
    }
}

fn tool_notes_list_spec() -> ToolSpec {
    ToolSpec {
        id: "notes_list".to_string(),
        name: "Notes List".to_string(),
        description: "Lists stored note IDs.".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        output_schema: serde_json::json!({
            "type": "object",
            "properties": { "note_ids": { "type": "array", "items": { "type": "integer" } } },
            "required": ["note_ids"],
            "additionalProperties": false
        }),
        category: ToolCategory::Read,
        cost: ToolCost::free(),
        output_firewall: briefcase_core::OutputFirewall::allow_all(),
    }
}
