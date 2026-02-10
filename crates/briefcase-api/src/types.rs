use briefcase_core::{ApprovalRequest, ProfileMode, ReceiptRecord, ToolCall, ToolResult, ToolSpec};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityResponse {
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_mode: Option<ProfileMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compatibility_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileResponse {
    pub mode: ProfileMode,
    pub compatibility_profile: String,
    pub strict_enforcement: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityDiagnosticsResponse {
    pub mode: ProfileMode,
    pub compatibility_profile: String,
    pub checks: Vec<CompatibilityCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDiagnosticsResponse {
    pub mode: ProfileMode,
    pub compatibility_profile: String,
    pub checks: Vec<CompatibilityCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlPlaneStatusResponse {
    NotEnrolled,
    Enrolled {
        base_url: String,
        device_id: Uuid,
        policy_signing_pubkey_b64: String,
        last_policy_bundle_id: Option<i64>,
        last_receipt_upload_id: i64,
        last_sync_at_rfc3339: Option<String>,
        last_error: Option<String>,
        updated_at_rfc3339: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneEnrollRequest {
    pub base_url: String,
    /// Admin bearer token for `/v1/admin/*` endpoints. This is used only for enrollment and is
    /// never persisted in the daemon.
    pub admin_token: String,
    pub device_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlPlaneSyncResponse {
    NotEnrolled,
    Synced {
        policy_applied: bool,
        receipts_uploaded: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSummary {
    pub id: String,
    pub base_url: String,
    pub has_oauth_refresh: bool,
    pub has_vc: bool,
    pub vc_expires_at_rfc3339: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListProvidersResponse {
    pub providers: Vec<ProviderSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertProviderRequest {
    pub base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteProviderResponse {
    pub provider_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeProviderOAuthResponse {
    pub provider_id: String,
    pub had_refresh_token: bool,
    pub remote_revocation_attempted: bool,
    pub remote_revocation_succeeded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerSummary {
    pub id: String,
    pub endpoint_url: String,
    pub has_oauth_refresh: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListMcpServersResponse {
    pub servers: Vec<McpServerSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertMcpServerRequest {
    pub endpoint_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteMcpServerResponse {
    pub server_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeMcpOAuthResponse {
    pub server_id: String,
    pub had_refresh_token: bool,
    pub remote_revocation_attempted: bool,
    pub remote_revocation_succeeded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpOAuthStartRequest {
    pub client_id: String,
    pub redirect_uri: String,
    /// OAuth scope string (space-separated). Optional; provider defaults may apply.
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpOAuthStartResponse {
    pub server_id: String,
    pub authorization_url: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpOAuthExchangeRequest {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpOAuthExchangeResponse {
    pub server_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthExchangeRequest {
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub code_verifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthExchangeResponse {
    pub provider_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchVcResponse {
    pub provider_id: String,
    pub expires_at_rfc3339: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReceiptsResponse {
    pub ok: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiSeverity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AiAnomalyKind {
    SpendSpike,
    OutputPoisoning,
    ExpensiveCall,
    NewDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiAnomaly {
    pub kind: AiAnomalyKind,
    pub severity: AiSeverity,
    pub message: String,
    pub receipt_id: Option<i64>,
    pub ts_rfc3339: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnomaliesResponse {
    pub anomalies: Vec<AiAnomaly>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetRecord {
    pub category: String,
    pub daily_limit_microusd: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListBudgetsResponse {
    pub budgets: Vec<BudgetRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetBudgetRequest {
    pub daily_limit_microusd: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGetResponse {
    pub policy_text: String,
    pub policy_hash_hex: String,
    pub updated_at_rfc3339: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCompileRequest {
    /// Natural language policy request (untrusted input).
    pub prompt: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDiffOp {
    Context,
    Add,
    Remove,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDiffLine {
    pub op: PolicyDiffOp,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyProposal {
    pub id: Uuid,
    pub created_at_rfc3339: String,
    pub expires_at_rfc3339: String,
    pub prompt: String,
    pub base_policy_hash_hex: String,
    pub proposed_policy_hash_hex: String,
    pub diff: Vec<PolicyDiffLine>,
    pub proposed_policy_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCompileResponse {
    pub proposal: PolicyProposal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PolicyApplyResponse {
    Applied {
        policy_hash_hex: String,
        updated_at_rfc3339: String,
    },
    ApprovalRequired {
        approval: ApprovalRequest,
    },
    Denied {
        reason: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignerAlgorithm {
    /// 32-byte Ed25519 public key.
    Ed25519,
    /// SEC1-encoded P-256 public key bytes (compressed or uncompressed).
    P256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerPairStartResponse {
    pub pairing_id: Uuid,
    /// Short-lived pairing code (base64url). Treat as a secret.
    pub pairing_code: String,
    pub expires_at_rfc3339: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerPairCompleteRequest {
    /// Noise handshake message 1 (base64url).
    pub msg1_b64: String,
    /// Signer public key algorithm.
    pub algorithm: SignerAlgorithm,
    /// Signer public key bytes (base64url).
    ///
    /// - `ed25519`: 32 raw bytes.
    /// - `p256`: SEC1-encoded bytes (33-byte compressed or 65-byte uncompressed).
    pub signer_pubkey_b64: String,
    /// Optional UI label for the signer device.
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerPairCompleteResponse {
    /// Noise handshake message 2 (base64url).
    pub msg2_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerSignedRequest {
    pub signer_id: Uuid,
    pub ts_rfc3339: String,
    pub nonce: String,
    pub sig_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListToolsResponse {
    pub tools: Vec<ToolSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CallToolResponse {
    Ok { result: ToolResult },
    ApprovalRequired { approval: ApprovalRequest },
    Denied { reason: String },
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolRequest {
    pub call: ToolCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListApprovalsResponse {
    pub approvals: Vec<ApprovalRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveResponse {
    pub approval_id: Uuid,
    /// Present this token in `ToolCall.approval_token`.
    pub approval_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListReceiptsResponse {
    pub receipts: Vec<ReceiptRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}
