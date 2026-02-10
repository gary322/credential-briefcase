use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context as _;
use base64::Engine as _;
use briefcase_control_plane_api::ControlPlaneClient;
use briefcase_control_plane_api::types::{
    AdminSetPolicyRequest, EnrollDeviceRequest, UploadReceiptsRequest,
};
use briefcase_core::ReceiptRecord;
use briefcase_keys::{KeyAlgorithm, SoftwareKeyManager};
use chrono::Utc;
use clap::Parser;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "enterprise-control-plane-harness",
    version,
    about = "CI harness for control-plane device enrollment + DPoP-secured sync"
)]
struct Args {
    /// Control plane base URL (http(s)://host:port).
    #[arg(long, env = "CONTROL_PLANE_BASE_URL")]
    base_url: String,
}

fn required_env(name: &str) -> anyhow::Result<String> {
    let v = std::env::var(name).with_context(|| format!("missing env {name}"))?;
    let v = v.trim().to_string();
    if v.is_empty() {
        anyhow::bail!("env {name} is empty");
    }
    Ok(v)
}

fn build_receipts() -> anyhow::Result<Vec<ReceiptRecord>> {
    use briefcase_core::util::sha256_hex_concat;

    let mut receipts = Vec::new();
    let mut prev = "0".repeat(64);
    for id in [1i64, 2i64] {
        let event = serde_json::json!({
            "kind": "tool_call",
            "tool_id": "echo",
            "decision": "allow",
            "cost_usd": 0.0
        });
        let event_json = serde_json::to_string(&event).context("serialize event")?;
        let hash_hex = sha256_hex_concat(&prev, event_json.as_bytes());
        receipts.push(ReceiptRecord {
            id,
            ts: Utc::now(),
            prev_hash_hex: prev,
            hash_hex: hash_hex.clone(),
            event,
        });
        prev = hash_hex;
    }
    Ok(receipts)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let admin_token = required_env("CONTROL_PLANE_ADMIN_TOKEN")?;
    let auditor_token = required_env("CONTROL_PLANE_AUDITOR_TOKEN")?;

    let base_url = Url::parse(&args.base_url).context("parse --base-url")?;
    let client = ControlPlaneClient::new(&args.base_url)?;

    // 1) Set a known policy bundle.
    let policy_text = "permit(principal, action, resource);".to_string();
    let budgets: BTreeMap<String, i64> = BTreeMap::from([
        ("read".to_string(), 3_000_000),
        ("write".to_string(), 0),
        ("admin".to_string(), 0),
    ]);
    let _ = client
        .admin_set_policy(
            &admin_token,
            AdminSetPolicyRequest {
                policy_text,
                budgets: budgets.clone(),
            },
        )
        .await
        .context("admin_set_policy")?;

    // 2) Generate a device identity key and enroll.
    let secrets = Arc::new(briefcase_secrets::InMemorySecretStore::default());
    let keys = SoftwareKeyManager::new(secrets);
    let handle = keys.generate(KeyAlgorithm::Ed25519).await?;
    let signer = keys.signer(handle);
    let pk = signer.public_key_bytes().await?;
    let device_pubkey_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk);

    let device_id = Uuid::new_v4();
    let enroll = client
        .admin_enroll_device(
            &admin_token,
            EnrollDeviceRequest {
                device_id,
                device_name: "ci-device".to_string(),
                device_pubkey_b64,
            },
        )
        .await
        .context("admin_enroll_device")?;
    let device_token = enroll.device_token;

    // 3) Fetch policy as device with DPoP (anti-replay + PoP binding).
    let policy_url = base_url
        .join(&format!("/v1/devices/{device_id}/policy"))
        .context("join policy url")?;
    let policy_dpop = briefcase_dpop::dpop_proof_for_resource_request(
        signer.as_ref(),
        &policy_url,
        "GET",
        &device_token,
    )
    .await
    .context("dpop_proof policy")?;
    let _ = client
        .device_get_policy(&device_id, &device_token, Some(&policy_dpop))
        .await
        .context("device_get_policy")?;

    // 4) Upload receipts as device with DPoP.
    let receipts_url = base_url
        .join(&format!("/v1/devices/{device_id}/receipts"))
        .context("join receipts url")?;
    let receipts_dpop = briefcase_dpop::dpop_proof_for_resource_request(
        signer.as_ref(),
        &receipts_url,
        "POST",
        &device_token,
    )
    .await
    .context("dpop_proof receipts")?;
    let receipts = build_receipts().context("build receipts")?;
    let upload = client
        .device_upload_receipts(
            &device_id,
            &device_token,
            Some(&receipts_dpop),
            UploadReceiptsRequest { receipts },
        )
        .await
        .context("device_upload_receipts")?;
    if upload.stored < 2 {
        anyhow::bail!("expected at least 2 receipts stored, got {}", upload.stored);
    }

    // 5) Audit receipts.
    let audit = client
        .audit_list_receipts(&auditor_token, Some(&device_id), 10, 0)
        .await
        .context("audit_list_receipts")?;
    if audit.receipts.len() < 2 {
        anyhow::bail!("expected at least 2 receipts in audit response");
    }

    println!("[enterprise] ok");
    Ok(())
}
