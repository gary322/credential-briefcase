use serde::{Deserialize, Serialize};

use crate::ToolId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolRuntimeKind {
    Builtin,
    Wasm,
    RemoteMcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEgressPolicy {
    /// Explicit allowlist of destination hosts (domain names or IP literals).
    pub allowed_hosts: Vec<String>,

    /// Optional per-tool HTTP path allowlist, enforced for provider-bound requests.
    ///
    /// Security note:
    /// - This is intentionally separate from `allowed_hosts` so that a tool cannot request
    ///   sensitive endpoints (e.g. `/token`) on an otherwise allowed host and then exfiltrate
    ///   the response to the agent.
    pub allowed_http_path_prefixes: Vec<String>,
}

impl ToolEgressPolicy {
    pub fn deny_all() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_http_path_prefixes: Vec::new(),
        }
    }

    pub fn allows_host(&self, host: &str) -> bool {
        self.allowed_hosts.iter().any(|h| h == host)
    }

    pub fn allows_http_path(&self, path: &str) -> bool {
        self.allowed_http_path_prefixes
            .iter()
            .any(|p| path.starts_with(p))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolFilesystemPolicy {
    /// Explicit allowlist of canonicalized filesystem path prefixes.
    pub allowed_path_prefixes: Vec<String>,
}

impl ToolFilesystemPolicy {
    pub fn deny_all() -> Self {
        Self {
            allowed_path_prefixes: Vec::new(),
        }
    }

    pub fn allows_path_prefix(&self, prefix: &str) -> bool {
        self.allowed_path_prefixes.iter().any(|p| p == prefix)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolLimits {
    pub max_output_bytes: u64,
}

impl Default for ToolLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifest {
    pub tool_id: ToolId,
    pub runtime: ToolRuntimeKind,
    pub egress: ToolEgressPolicy,
    pub filesystem: ToolFilesystemPolicy,
    pub limits: ToolLimits,
}

impl ToolManifest {
    pub fn deny_all(tool_id: impl Into<ToolId>, runtime: ToolRuntimeKind) -> Self {
        Self {
            tool_id: tool_id.into(),
            runtime,
            egress: ToolEgressPolicy::deny_all(),
            filesystem: ToolFilesystemPolicy::deny_all(),
            limits: ToolLimits::default(),
        }
    }
}
