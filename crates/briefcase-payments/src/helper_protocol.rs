//! JSON protocol between `briefcased` and an external payment helper program.
//!
//! The helper is intended to keep high-risk secrets (wallet private keys, Lightning node creds)
//! out of the long-lived daemon process. The daemon sends a single JSON request on stdin and
//! expects a single JSON response on stdout.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{PaymentChallenge, x402};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum PaymentHelperRequest {
    /// Legacy/demo x402: daemon expects the helper to return an opaque proof string.
    X402 {
        provider_base_url: String,
        payment_id: String,
        payment_url: String,
        amount_microusd: i64,
    },

    /// x402 v2 (HTTP transport): helper returns a base64-encoded `PaymentPayload` to be sent as
    /// `PAYMENT-SIGNATURE`.
    X402V2 {
        provider_base_url: String,
        payment_required: x402::PaymentRequired,
    },

    /// L402: helper pays the BOLT11 invoice via a Lightning backend and returns the preimage;
    /// daemon attaches macaroon+preimage.
    L402 {
        provider_base_url: String,
        invoice: String,
        macaroon: String,
        amount_microusd: i64,
    },
}

impl PaymentHelperRequest {
    pub fn from_legacy_challenge(provider_base_url: &Url, ch: PaymentChallenge) -> Self {
        match ch {
            PaymentChallenge::X402 {
                payment_id,
                payment_url,
                amount_microusd,
            } => Self::X402 {
                provider_base_url: provider_base_url.to_string(),
                payment_id,
                payment_url,
                amount_microusd,
            },
            PaymentChallenge::L402 {
                invoice,
                macaroon,
                amount_microusd,
            } => Self::L402 {
                provider_base_url: provider_base_url.to_string(),
                invoice,
                macaroon,
                amount_microusd,
            },
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum PaymentHelperResponse {
    X402 { proof: String },
    X402V2 { payment_signature_b64: String },
    L402 { preimage: String },
}
