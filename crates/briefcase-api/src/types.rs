use briefcase_core::{ApprovalRequest, ReceiptRecord, ToolCall, ToolResult, ToolSpec};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityResponse {
    pub did: String,
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
