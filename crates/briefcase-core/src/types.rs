use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type ToolId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    Read,
    Write,
    Admin,
    Other(String),
}

impl ToolCategory {
    pub fn as_str(&self) -> &str {
        match self {
            ToolCategory::Read => "read",
            ToolCategory::Write => "write",
            ToolCategory::Admin => "admin",
            ToolCategory::Other(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCost {
    pub estimated_usd: f64,
}

impl ToolCost {
    pub const fn free() -> Self {
        Self { estimated_usd: 0.0 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFirewallMode {
    AllowAll,
    AllowPaths,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputFirewall {
    pub mode: OutputFirewallMode,
    /// Dot-separated JSON pointer-ish paths, e.g. `data.symbol` or `quote.price`.
    pub allowed_paths: Vec<String>,
}

impl OutputFirewall {
    pub fn allow_all() -> Self {
        Self {
            mode: OutputFirewallMode::AllowAll,
            allowed_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub id: ToolId,
    pub name: String,
    pub description: String,
    /// JSON Schema for tool arguments.
    pub input_schema: serde_json::Value,
    /// JSON Schema for tool output.
    pub output_schema: serde_json::Value,
    pub category: ToolCategory,
    pub cost: ToolCost,
    pub output_firewall: OutputFirewall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallContext {
    pub request_id: Uuid,
    pub agent_id: Option<String>,
    pub session_id: Option<String>,
}

impl ToolCallContext {
    pub fn new() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            agent_id: None,
            session_id: None,
        }
    }
}

impl Default for ToolCallContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool_id: ToolId,
    pub args: serde_json::Value,
    pub context: ToolCallContext,
    /// When present, proves the user approved a previously-blocked call.
    pub approval_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String, kind: ApprovalKind },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// Approval can be satisfied via local UI (extension/CLI) using the daemon auth token.
    Local,
    /// Approval must be satisfied via a paired mobile signer (signature-based auth).
    MobileSigner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    None,
    OAuth,
    Vc,
    CapabilityToken,
    PaymentX402,
    PaymentL402,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub source: String,
    pub cost_usd: Option<f64>,
    pub timestamp: DateTime<Utc>,
    pub receipt_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub content: serde_json::Value,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub tool_id: ToolId,
    pub reason: String,
    pub kind: ApprovalKind,
    pub summary: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptRecord {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub prev_hash_hex: String,
    pub hash_hex: String,
    pub event: serde_json::Value,
}
