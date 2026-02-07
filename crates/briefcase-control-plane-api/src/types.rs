use std::collections::BTreeMap;

use briefcase_core::ReceiptRecord;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollDeviceRequest {
    pub device_id: Uuid,
    pub device_name: String,
    /// Device public key (base64url, untrusted; used for future attestation).
    pub device_pubkey_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Monotonic bundle ID (DB primary key).
    pub bundle_id: i64,
    pub policy_text: String,
    /// Category -> daily_limit_microusd.
    pub budgets: BTreeMap<String, i64>,
    pub updated_at_rfc3339: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicyBundle {
    pub bundle: PolicyBundle,
    /// Ed25519 signature over `serde_json::to_vec(&bundle)` (base64url).
    pub signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollDeviceResponse {
    pub device_id: Uuid,
    /// Device bearer token (treat as a secret).
    pub device_token: String,
    /// Ed25519 public key used to verify policy bundle signatures (base64url).
    pub policy_signing_pubkey_b64: String,
    pub policy_bundle: SignedPolicyBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSetPolicyRequest {
    pub policy_text: String,
    pub budgets: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSetPolicyResponse {
    pub policy_bundle: SignedPolicyBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePolicyResponse {
    pub policy_bundle: SignedPolicyBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadReceiptsRequest {
    pub receipts: Vec<ReceiptRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadReceiptsResponse {
    pub stored: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditListReceiptsResponse {
    pub receipts: Vec<ReceiptRecord>,
}
