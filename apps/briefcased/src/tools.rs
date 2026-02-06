use std::collections::HashMap;
use std::sync::Arc;

use briefcase_core::{AuthMethod, OutputFirewallMode, ToolCategory, ToolCost, ToolSpec};
use jsonschema::Validator;
use thiserror::Error;

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

        tools.insert(
            "echo".to_string(),
            Arc::new(ToolRuntime::new(tool_echo_spec(), ToolImpl::Echo).expect("valid schema")),
        );

        tools.insert(
            "quote".to_string(),
            Arc::new(
                ToolRuntime::new(tool_quote_spec(), ToolImpl::Quote { provider })
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
    Quote { provider: Arc<ProviderClient> },
    NoteAdd { db: Db },
    NotesList { db: Db },
}

#[derive(Debug, Error)]
pub enum ToolRuntimeError {
    #[error("execution error: {0}")]
    Exec(String),
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
            ToolImpl::Quote { provider } => provider
                .get_quote(args)
                .await
                .map_err(|e| ToolRuntimeError::Exec(e.to_string())),
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
