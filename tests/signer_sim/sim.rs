use anyhow::Context as _;
use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::Signer as _;
use rand::RngCore as _;
use uuid::Uuid;

pub struct SimSigner {
    signing_key: ed25519_dalek::SigningKey,
}

impl SimSigner {
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        Self {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    pub fn pubkey_b64(&self) -> String {
        let vk = self.signing_key.verifying_key();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.to_bytes())
    }

    pub async fn pair(
        &self,
        client: &briefcase_api::BriefcaseClient,
        pairing_id: Uuid,
        pairing_code_b64: &str,
    ) -> anyhow::Result<Uuid> {
        let psk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(pairing_code_b64.as_bytes())
            .context("decode pairing_code")?;
        if psk_bytes.len() != 32 {
            anyhow::bail!("pairing_code wrong length");
        }
        let mut psk = [0u8; 32];
        psk.copy_from_slice(&psk_bytes);

        let mut noise = crate::pairing::noise_initiator(&psk)?;
        let mut msg1 = vec![0u8; 1024];
        let msg1_len = noise
            .write_message(&[], &mut msg1)
            .context("noise write msg1")?;
        msg1.truncate(msg1_len);

        let resp = client
            .signer_pair_complete(
                &pairing_id,
                briefcase_api::types::SignerPairCompleteRequest {
                    msg1_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(msg1),
                    algorithm: briefcase_api::types::SignerAlgorithm::Ed25519,
                    signer_pubkey_b64: self.pubkey_b64(),
                    device_name: Some("sim".to_string()),
                },
            )
            .await?;

        let msg2 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(resp.msg2_b64.as_bytes())
            .context("decode msg2")?;
        let mut payload = vec![0u8; 1024];
        let payload_len = noise
            .read_message(&msg2, &mut payload)
            .context("noise read msg2")?;
        payload.truncate(payload_len);

        let v: serde_json::Value =
            serde_json::from_slice(&payload).context("decode msg2 payload json")?;
        let signer_id = v
            .get("signer_id")
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        Uuid::parse_str(signer_id).context("parse signer_id")
    }

    pub fn signed_request(
        &self,
        signer_id: Uuid,
        kind: &str,
        approval_id: Option<Uuid>,
    ) -> briefcase_api::types::SignerSignedRequest {
        let ts_rfc3339 = Utc::now().to_rfc3339();
        let nonce = Uuid::new_v4().to_string();
        let approval_line = approval_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "-".to_string());
        let msg = format!(
            "{kind}\n{signer_id}\n{approval_line}\n{ts_rfc3339}\n{nonce}\n"
        );
        let sig = self.signing_key.sign(msg.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

        briefcase_api::types::SignerSignedRequest {
            signer_id,
            ts_rfc3339,
            nonce,
            sig_b64,
        }
    }
}

pub struct SimP256Signer {
    signing_key: p256::ecdsa::SigningKey,
}

impl SimP256Signer {
    pub fn new() -> Self {
        let mut rng = p256::elliptic_curve::rand_core::OsRng;
        Self {
            signing_key: p256::ecdsa::SigningKey::random(&mut rng),
        }
    }

    pub fn pubkey_b64(&self) -> String {
        let vk = self.signing_key.verifying_key();
        let point = vk.to_encoded_point(false);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.as_bytes())
    }

    pub async fn pair(
        &self,
        client: &briefcase_api::BriefcaseClient,
        pairing_id: Uuid,
        pairing_code_b64: &str,
    ) -> anyhow::Result<Uuid> {
        let psk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(pairing_code_b64.as_bytes())
            .context("decode pairing_code")?;
        if psk_bytes.len() != 32 {
            anyhow::bail!("pairing_code wrong length");
        }
        let mut psk = [0u8; 32];
        psk.copy_from_slice(&psk_bytes);

        let mut noise = crate::pairing::noise_initiator(&psk)?;
        let mut msg1 = vec![0u8; 1024];
        let msg1_len = noise
            .write_message(&[], &mut msg1)
            .context("noise write msg1")?;
        msg1.truncate(msg1_len);

        let resp = client
            .signer_pair_complete(
                &pairing_id,
                briefcase_api::types::SignerPairCompleteRequest {
                    msg1_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(msg1),
                    algorithm: briefcase_api::types::SignerAlgorithm::P256,
                    signer_pubkey_b64: self.pubkey_b64(),
                    device_name: Some("sim-p256".to_string()),
                },
            )
            .await?;

        let msg2 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(resp.msg2_b64.as_bytes())
            .context("decode msg2")?;
        let mut payload = vec![0u8; 1024];
        let payload_len = noise
            .read_message(&msg2, &mut payload)
            .context("noise read msg2")?;
        payload.truncate(payload_len);

        let v: serde_json::Value =
            serde_json::from_slice(&payload).context("decode msg2 payload json")?;
        let signer_id = v
            .get("signer_id")
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        Uuid::parse_str(signer_id).context("parse signer_id")
    }

    pub fn signed_request(
        &self,
        signer_id: Uuid,
        kind: &str,
        approval_id: Option<Uuid>,
    ) -> briefcase_api::types::SignerSignedRequest {
        let ts_rfc3339 = Utc::now().to_rfc3339();
        let nonce = Uuid::new_v4().to_string();
        let approval_line = approval_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "-".to_string());
        let msg = format!(
            "{kind}\n{signer_id}\n{approval_line}\n{ts_rfc3339}\n{nonce}\n"
        );

        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.signing_key.sign(msg.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_der());

        briefcase_api::types::SignerSignedRequest {
            signer_id,
            ts_rfc3339,
            nonce,
            sig_b64,
        }
    }
}
