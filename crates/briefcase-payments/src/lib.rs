//! Payment rails and adapters.
//!
//! Design goals:
//! - Keep the LLM untrusted: payment proofs / preimages never flow through the agent runtime.
//! - Make "how to pay" pluggable: the default backend is a demo HTTP flow; production deployments
//!   can delegate payment to an external helper program.

use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use url::Url;

pub mod helper_protocol;
pub mod l402;
#[cfg(all(feature = "l402-cln", unix))]
pub mod l402_cln;
#[cfg(feature = "l402-lnd")]
pub mod l402_lnd;
pub mod x402;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum PaymentChallenge {
    X402 {
        payment_id: String,
        payment_url: String,
        amount_microusd: i64,
    },
    L402 {
        invoice: String,
        macaroon: String,
        amount_microusd: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentProof {
    X402 {
        proof: String,
    },
    /// x402 v2: value for the HTTP `PAYMENT-SIGNATURE` header (base64-encoded JSON PaymentPayload).
    X402V2 {
        payment_signature_b64: String,
    },
    L402 {
        macaroon: String,
        preimage: String,
    },
}

pub fn format_www_authenticate(challenge: &PaymentChallenge) -> String {
    match challenge {
        PaymentChallenge::X402 {
            payment_id,
            payment_url,
            amount_microusd,
        } => format!(
            "X402 payment_id=\"{payment_id}\", payment_url=\"{payment_url}\", amount_microusd={amount_microusd}"
        ),
        PaymentChallenge::L402 {
            invoice,
            macaroon,
            amount_microusd,
        } => format!(
            "L402 invoice=\"{invoice}\", macaroon=\"{macaroon}\", amount_microusd={amount_microusd}"
        ),
    }
}

pub fn parse_www_authenticate(value: &str) -> anyhow::Result<PaymentChallenge> {
    let v = value.trim();
    let (scheme, rest) = v.split_once(' ').context("missing auth scheme")?;
    let params = parse_kv_params(rest);

    match scheme {
        s if s.eq_ignore_ascii_case("x402") => Ok(PaymentChallenge::X402 {
            payment_id: params
                .get("payment_id")
                .cloned()
                .context("missing payment_id")?,
            payment_url: params
                .get("payment_url")
                .cloned()
                .context("missing payment_url")?,
            amount_microusd: params
                .get("amount_microusd")
                .context("missing amount_microusd")?
                .parse()
                .context("parse amount_microusd")?,
        }),
        s if s.eq_ignore_ascii_case("l402") => Ok(PaymentChallenge::L402 {
            invoice: params.get("invoice").cloned().context("missing invoice")?,
            macaroon: params
                .get("macaroon")
                .cloned()
                .context("missing macaroon")?,
            amount_microusd: params
                .get("amount_microusd")
                .context("missing amount_microusd")?
                .parse()
                .context("parse amount_microusd")?,
        }),
        other => anyhow::bail!("unsupported www-authenticate scheme: {other}"),
    }
}

fn parse_kv_params(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for part in s.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let Some((k, v)) = p.split_once('=') else {
            continue;
        };
        let key = k.trim().to_string();
        let mut val = v.trim().to_string();
        if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
            val = val[1..val.len() - 1].to_string();
        }
        out.insert(key, val);
    }
    out
}

#[async_trait]
pub trait PaymentBackend: Send + Sync {
    async fn pay(
        &self,
        provider_base_url: &Url,
        challenge: PaymentChallenge,
    ) -> anyhow::Result<PaymentProof>;

    /// Form an x402 v2 payment payload for the HTTP transport, returning `PaymentProof::X402V2`.
    ///
    /// Default implementation errors so legacy/demo deployments don't accidentally attempt to
    /// use x402 v2 without an explicit wallet backend.
    async fn pay_x402_v2(
        &self,
        _provider_base_url: &Url,
        _required: x402::PaymentRequired,
    ) -> anyhow::Result<PaymentProof> {
        anyhow::bail!("x402 v2 not supported by payment backend")
    }
}

#[derive(Clone)]
pub struct HttpDemoPaymentBackend {
    http: reqwest::Client,
}

impl HttpDemoPaymentBackend {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .context("build reqwest client")?,
        })
    }

    fn same_origin(a: &Url, b: &Url) -> bool {
        a.scheme() == b.scheme()
            && a.host_str() == b.host_str()
            && a.port_or_known_default() == b.port_or_known_default()
    }

    fn resolve_payment_url(
        &self,
        provider_base_url: &Url,
        payment_url: &str,
    ) -> anyhow::Result<Url> {
        if payment_url.starts_with("http://") || payment_url.starts_with("https://") {
            let u = Url::parse(payment_url).context("parse payment_url")?;
            if !Self::same_origin(provider_base_url, &u) {
                anyhow::bail!("payment_url not same-origin as provider_base_url");
            }
            return Ok(u);
        }

        provider_base_url
            .join(payment_url)
            .context("join relative payment_url")
    }
}

#[derive(Debug, Serialize)]
struct X402PayRequest<'a> {
    payment_id: &'a str,
}

#[derive(Debug, Deserialize)]
struct X402PayResponse {
    proof: String,
}

#[derive(Debug, Serialize)]
struct L402PayRequest<'a> {
    invoice: &'a str,
}

#[derive(Debug, Deserialize)]
struct L402PayResponse {
    preimage: String,
}

#[async_trait]
impl PaymentBackend for HttpDemoPaymentBackend {
    async fn pay(
        &self,
        provider_base_url: &Url,
        challenge: PaymentChallenge,
    ) -> anyhow::Result<PaymentProof> {
        match challenge {
            PaymentChallenge::X402 {
                payment_id,
                payment_url,
                ..
            } => {
                let url = self.resolve_payment_url(provider_base_url, &payment_url)?;
                let resp = self
                    .http
                    .post(url)
                    .json(&X402PayRequest {
                        payment_id: &payment_id,
                    })
                    .send()
                    .await
                    .context("x402 payment request")?;
                if !resp.status().is_success() {
                    anyhow::bail!("x402 payment failed: {}", resp.status());
                }
                let pr = resp
                    .json::<X402PayResponse>()
                    .await
                    .context("parse x402 pay response")?;
                Ok(PaymentProof::X402 { proof: pr.proof })
            }
            PaymentChallenge::L402 {
                invoice, macaroon, ..
            } => {
                let url = provider_base_url
                    .join("/l402/pay")
                    .context("join /l402/pay")?;
                let resp = self
                    .http
                    .post(url)
                    .json(&L402PayRequest { invoice: &invoice })
                    .send()
                    .await
                    .context("l402 payment request")?;
                if !resp.status().is_success() {
                    anyhow::bail!("l402 payment failed: {}", resp.status());
                }
                let pr = resp
                    .json::<L402PayResponse>()
                    .await
                    .context("parse l402 pay response")?;
                Ok(PaymentProof::L402 {
                    macaroon,
                    preimage: pr.preimage,
                })
            }
        }
    }

    async fn pay_x402_v2(
        &self,
        _provider_base_url: &Url,
        _required: x402::PaymentRequired,
    ) -> anyhow::Result<PaymentProof> {
        anyhow::bail!(
            "x402 v2 requires a wallet helper; set BRIEFCASE_PAYMENT_HELPER to a helper program"
        )
    }
}

#[derive(Clone)]
pub struct CommandPaymentBackend {
    program: String,
    args: Vec<String>,
    timeout: Duration,
}

impl CommandPaymentBackend {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[async_trait]
impl PaymentBackend for CommandPaymentBackend {
    async fn pay(
        &self,
        provider_base_url: &Url,
        challenge: PaymentChallenge,
    ) -> anyhow::Result<PaymentProof> {
        let req = helper_protocol::PaymentHelperRequest::from_legacy_challenge(
            provider_base_url,
            challenge.clone(),
        );
        let input = serde_json::to_vec(&req).context("encode payment helper request")?;

        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("spawn payment helper")?;
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt as _;
            stdin
                .write_all(&input)
                .await
                .context("write payment helper stdin")?;
        }

        let out = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .context("payment helper timeout")?
            .context("wait payment helper")?;

        if !out.status.success() {
            // Avoid accidentally leaking sensitive material (preimages, proofs) via logs.
            anyhow::bail!("payment helper failed with status {}", out.status);
        }

        let resp: helper_protocol::PaymentHelperResponse =
            serde_json::from_slice(&out.stdout).context("decode payment helper response")?;

        match (challenge, resp) {
            (
                PaymentChallenge::X402 { .. },
                helper_protocol::PaymentHelperResponse::X402 { proof },
            ) => Ok(PaymentProof::X402 { proof }),
            (
                PaymentChallenge::L402 { macaroon, .. },
                helper_protocol::PaymentHelperResponse::L402 { preimage },
            ) => Ok(PaymentProof::L402 { macaroon, preimage }),
            (
                PaymentChallenge::X402 { .. },
                helper_protocol::PaymentHelperResponse::L402 { .. },
            )
            | (
                PaymentChallenge::L402 { .. },
                helper_protocol::PaymentHelperResponse::X402 { .. },
            )
            | (
                PaymentChallenge::X402 { .. },
                helper_protocol::PaymentHelperResponse::X402V2 { .. },
            )
            | (
                PaymentChallenge::L402 { .. },
                helper_protocol::PaymentHelperResponse::X402V2 { .. },
            ) => {
                anyhow::bail!("payment helper rail mismatch")
            }
        }
    }

    async fn pay_x402_v2(
        &self,
        provider_base_url: &Url,
        required: x402::PaymentRequired,
    ) -> anyhow::Result<PaymentProof> {
        let req = helper_protocol::PaymentHelperRequest::X402V2 {
            provider_base_url: provider_base_url.to_string(),
            payment_required: required,
        };
        let input = serde_json::to_vec(&req).context("encode payment helper request")?;

        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().context("spawn payment helper")?;
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt as _;
            stdin
                .write_all(&input)
                .await
                .context("write payment helper stdin")?;
        }

        let out = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .context("payment helper timeout")?
            .context("wait payment helper")?;

        if !out.status.success() {
            anyhow::bail!("payment helper failed with status {}", out.status);
        }

        let resp: helper_protocol::PaymentHelperResponse =
            serde_json::from_slice(&out.stdout).context("decode payment helper response")?;

        match resp {
            helper_protocol::PaymentHelperResponse::X402V2 {
                payment_signature_b64,
            } => Ok(PaymentProof::X402V2 {
                payment_signature_b64,
            }),
            other => anyhow::bail!("payment helper rail mismatch: expected x402_v2, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn www_auth_round_trip_x402() {
        let ch = PaymentChallenge::X402 {
            payment_id: "p1".to_string(),
            payment_url: "/pay".to_string(),
            amount_microusd: 2000,
        };
        let h = format_www_authenticate(&ch);
        let parsed = parse_www_authenticate(&h).unwrap();
        assert_eq!(parsed, ch);
    }

    #[test]
    fn www_auth_round_trip_l402() {
        let ch = PaymentChallenge::L402 {
            invoice: "lnbc_demo".to_string(),
            macaroon: "mac".to_string(),
            amount_microusd: 123,
        };
        let h = format_www_authenticate(&ch);
        let parsed = parse_www_authenticate(&h).unwrap();
        assert_eq!(parsed, ch);
    }

    #[test]
    fn x402_b64_round_trip_payment_required() {
        let pr = x402::PaymentRequired {
            x402_version: 2,
            error: Some("missing payment".to_string()),
            resource: x402::ResourceInfo {
                url: "https://api.example.com/premium".to_string(),
                description: Some("premium".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            accepts: vec![x402::PaymentRequirements {
                scheme: "exact".to_string(),
                network: "eip155:84532".to_string(),
                amount: "10000".to_string(),
                asset: "0x0000000000000000000000000000000000000000".to_string(),
                pay_to: "0x1111111111111111111111111111111111111111".to_string(),
                max_timeout_seconds: 60,
                extra: serde_json::json!({"assetTransferMethod":"eip3009","name":"USD Coin","version":"2"}),
            }],
            extensions: serde_json::json!({}),
        };
        let b64 = x402::encode_payment_required_b64(&pr).unwrap();
        let parsed = x402::decode_payment_required_b64(&b64).unwrap();
        assert_eq!(parsed, pr);
    }

    #[test]
    fn x402_b64_round_trip_payment_payload() {
        let payload = x402::PaymentPayload {
            x402_version: 2,
            resource: Some(x402::ResourceInfo {
                url: "https://api.example.com/premium".to_string(),
                description: None,
                mime_type: None,
            }),
            accepted: x402::PaymentRequirements {
                scheme: "exact".to_string(),
                network: "eip155:84532".to_string(),
                amount: "10000".to_string(),
                asset: "0x0000000000000000000000000000000000000000".to_string(),
                pay_to: "0x1111111111111111111111111111111111111111".to_string(),
                max_timeout_seconds: 60,
                extra: serde_json::json!({"assetTransferMethod":"eip3009","name":"USD Coin","version":"2"}),
            },
            payload: serde_json::json!({"signature":"0x00","authorization":{"from":"0x00","to":"0x00","value":"1","validAfter":"0","validBefore":"1","nonce":"0x00"}}),
            extensions: serde_json::json!({}),
        };
        let b64 = x402::encode_payment_payload_b64(&payload).unwrap();
        let parsed = x402::decode_payment_payload_b64(&b64).unwrap();
        assert_eq!(parsed, payload);
    }
}
