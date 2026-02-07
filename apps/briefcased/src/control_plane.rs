use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use briefcase_control_plane_api::ControlPlaneClient;
use briefcase_control_plane_api::types::{
    DevicePolicyResponse, EnrollDeviceRequest, EnrollDeviceResponse, UploadReceiptsRequest,
};
use briefcase_core::ReceiptRecord;
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use tokio::time;
use tracing::{info, warn};
use uuid::Uuid;

use crate::app::AppState;
use crate::db::ControlPlaneRecord;
use briefcase_keys::{KeyAlgorithm, KeyHandle, SoftwareKeyManager};
use briefcase_policy::{CedarPolicyEngine, CedarPolicyEngineOptions};

const DEVICE_TOKEN_SECRET_KEY: &str = "control_plane.device_token";

#[derive(Debug, Clone, Default)]
pub struct ControlPlaneSyncOutcome {
    pub policy_applied: bool,
    pub receipts_uploaded: usize,
}

pub fn spawn_control_plane_worker(state: AppState) -> tokio::task::JoinHandle<()> {
    let interval_secs: u64 = std::env::var("BRIEFCASE_CONTROL_PLANE_SYNC_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(60);

    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            if let Err(e) = sync_once(&state).await {
                warn!(error = %e, "control plane sync failed");
                let msg = truncate_err(&e.to_string(), 200);
                let _ = state
                    .db
                    .update_control_plane_sync_status(Utc::now(), Some(msg.as_str()))
                    .await;
            }
        }
    })
}

pub async fn status(state: &AppState) -> anyhow::Result<Option<ControlPlaneRecord>> {
    state.db.control_plane().await
}

pub async fn enroll(
    state: &AppState,
    base_url: &str,
    admin_token: &str,
    device_name: &str,
) -> anyhow::Result<ControlPlaneRecord> {
    let base_url = normalize_control_plane_base_url(base_url)?;

    let device_id = match state.db.control_plane().await? {
        Some(existing) => existing.device_id,
        None => Uuid::new_v4(),
    };

    let device_pubkey_b64 = identity_pubkey_b64(state).await?;
    let client = ControlPlaneClient::new(&base_url)?;

    let resp: EnrollDeviceResponse = client
        .admin_enroll_device(
            admin_token,
            EnrollDeviceRequest {
                device_id,
                device_name: device_name.to_string(),
                device_pubkey_b64,
            },
        )
        .await?;

    // Verify signature before persisting enrollment.
    verify_policy_bundle_signature(
        &resp.policy_signing_pubkey_b64,
        &resp.policy_bundle.bundle,
        &resp.policy_bundle.signature_b64,
    )?;

    // Persist token/config first so enrollment is complete only if the policy bundle applies.
    // Best-effort rollback is performed on failure.
    state
        .secrets
        .put(
            DEVICE_TOKEN_SECRET_KEY,
            briefcase_core::Sensitive(resp.device_token.as_bytes().to_vec()),
        )
        .await?;

    if let Err(e) = state
        .db
        .upsert_control_plane_enrollment(
            &base_url,
            device_id,
            &resp.policy_signing_pubkey_b64,
            Some(resp.policy_bundle.bundle.bundle_id),
        )
        .await
    {
        let _ = state.secrets.delete(DEVICE_TOKEN_SECRET_KEY).await;
        return Err(e).context("persist control plane enrollment");
    }

    if let Err(e) =
        apply_policy_bundle(state, &resp.policy_signing_pubkey_b64, &resp.policy_bundle).await
    {
        let _ = state.db.delete_control_plane_enrollment().await;
        let _ = state.secrets.delete(DEVICE_TOKEN_SECRET_KEY).await;
        return Err(e).context("apply control plane policy bundle");
    }

    let _ = state
        .receipts
        .append(serde_json::json!({
            "kind": "control_plane_enroll",
            "base_url": base_url,
            "device_id": device_id,
            "ts": Utc::now().to_rfc3339(),
        }))
        .await;

    let rec = state
        .db
        .control_plane()
        .await?
        .context("control plane record missing after enroll")?;
    Ok(rec)
}

pub async fn sync_once(state: &AppState) -> anyhow::Result<ControlPlaneSyncOutcome> {
    let Some(cfg) = state.db.control_plane().await? else {
        return Ok(ControlPlaneSyncOutcome::default());
    };

    let device_token = state
        .secrets
        .get(DEVICE_TOKEN_SECRET_KEY)
        .await?
        .context("missing control plane device token")?
        .into_inner();
    let device_token = String::from_utf8(device_token).context("device token is not utf8")?;

    let client = ControlPlaneClient::new(&cfg.base_url)?;

    let policy: DevicePolicyResponse = client
        .device_get_policy(&cfg.device_id, &device_token)
        .await?;

    verify_policy_bundle_signature(
        &cfg.policy_signing_pubkey_b64,
        &policy.policy_bundle.bundle,
        &policy.policy_bundle.signature_b64,
    )?;

    let mut outcome = ControlPlaneSyncOutcome::default();

    let bundle_id = policy.policy_bundle.bundle.bundle_id;
    if cfg
        .last_policy_bundle_id
        .map(|cur| bundle_id > cur)
        .unwrap_or(true)
    {
        apply_policy_bundle(state, &cfg.policy_signing_pubkey_b64, &policy.policy_bundle).await?;
        state
            .db
            .set_control_plane_last_policy_bundle_id(bundle_id)
            .await?;
        outcome.policy_applied = true;
    }

    // Upload new receipts (best-effort).
    let uploaded = upload_new_receipts(state, &client, &cfg, &device_token).await?;
    outcome.receipts_uploaded = uploaded;

    let _ = state
        .db
        .update_control_plane_sync_status(Utc::now(), None)
        .await;
    Ok(outcome)
}

async fn upload_new_receipts(
    state: &AppState,
    client: &ControlPlaneClient,
    cfg: &ControlPlaneRecord,
    device_token: &str,
) -> anyhow::Result<usize> {
    let mut receipts =
        collect_receipts_after_id(&state.receipts, cfg.last_receipt_upload_id).await?;
    if receipts.is_empty() {
        return Ok(0);
    }

    receipts.sort_by_key(|r| r.id);
    let mut uploaded_total = 0usize;

    for chunk in receipts.chunks(500) {
        let max_id = chunk
            .last()
            .map(|r| r.id)
            .unwrap_or(cfg.last_receipt_upload_id);
        let resp = client
            .device_upload_receipts(
                &cfg.device_id,
                device_token,
                UploadReceiptsRequest {
                    receipts: chunk.to_vec(),
                },
            )
            .await?;
        uploaded_total += resp.stored;
        state
            .db
            .set_control_plane_last_receipt_upload_id(max_id)
            .await?;
    }

    Ok(uploaded_total)
}

async fn collect_receipts_after_id(
    store: &briefcase_receipts::ReceiptStore,
    after_id: i64,
) -> anyhow::Result<Vec<ReceiptRecord>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    let page_limit = 500usize;

    loop {
        let page = store
            .list(page_limit, offset)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        if page.is_empty() {
            break;
        }

        for r in &page {
            if r.id > after_id {
                out.push(r.clone());
            }
        }

        let oldest = page.last().map(|r| r.id).unwrap_or(0);
        if oldest <= after_id {
            break;
        }

        offset = offset.saturating_add(page.len());
        if offset > 50_000 {
            // Hard stop: avoid unbounded scans if the watermark is missing/corrupt.
            break;
        }
    }

    Ok(out)
}

async fn apply_policy_bundle(
    state: &AppState,
    policy_pubkey_b64: &str,
    signed: &briefcase_control_plane_api::types::SignedPolicyBundle,
) -> anyhow::Result<()> {
    verify_policy_bundle_signature(policy_pubkey_b64, &signed.bundle, &signed.signature_b64)?;

    let engine = CedarPolicyEngine::new(CedarPolicyEngineOptions {
        policy_text: signed.bundle.policy_text.clone(),
    })
    .context("compile cedar policy")?;

    let rec = state
        .db
        .apply_policy_and_budgets(&signed.bundle.policy_text, &signed.bundle.budgets)
        .await?;
    *state.policy.write().await = std::sync::Arc::new(engine);

    let _ = state
        .receipts
        .append(serde_json::json!({
            "kind": "control_plane_policy_sync",
            "bundle_id": signed.bundle.bundle_id,
            "policy_hash_hex": rec.policy_hash_hex,
            "budgets": signed.bundle.budgets,
            "ts": Utc::now().to_rfc3339(),
        }))
        .await;

    info!(
        bundle_id = signed.bundle.bundle_id,
        "applied control plane policy bundle"
    );
    Ok(())
}

fn verify_policy_bundle_signature(
    pubkey_b64: &str,
    bundle: &briefcase_control_plane_api::types::PolicyBundle,
    signature_b64: &str,
) -> anyhow::Result<()> {
    let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(pubkey_b64.as_bytes())
        .context("decode pubkey")?;
    if pk.len() != 32 {
        anyhow::bail!("invalid pubkey length");
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk);
    let vk = VerifyingKey::from_bytes(&pk_arr).context("decode ed25519 pubkey")?;

    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .context("decode signature")?;
    let sig = Signature::from_slice(&sig_bytes).context("decode ed25519 signature")?;

    let bytes = serde_json::to_vec(bundle).context("serialize bundle")?;
    vk.verify_strict(&bytes, &sig)
        .context("verify policy bundle signature")?;
    Ok(())
}

async fn identity_pubkey_b64(state: &AppState) -> anyhow::Result<String> {
    let keys = SoftwareKeyManager::new(state.secrets.clone());
    let handle_json = state
        .secrets
        .get("identity.key_handle")
        .await?
        .context("missing identity.key_handle")?
        .into_inner();
    let handle = KeyHandle::from_json(&handle_json).context("decode identity.key_handle")?;
    if handle.algorithm != KeyAlgorithm::Ed25519 {
        anyhow::bail!("identity key must be ed25519");
    }
    let signer = keys.signer(handle);
    let pk = signer.public_key_bytes().await?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk))
}

fn normalize_control_plane_base_url(base_url: &str) -> anyhow::Result<String> {
    let raw = base_url.trim().trim_end_matches('/').to_string();
    let u = url::Url::parse(&raw).context("parse base_url")?;
    match u.scheme() {
        "https" => {}
        "http" => {
            let host = u.host().context("missing host")?;
            let is_loopback = match host {
                url::Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
                url::Host::Ipv4(ip) => ip.is_loopback(),
                url::Host::Ipv6(ip) => ip.is_loopback(),
            };
            if !is_loopback {
                anyhow::bail!("control plane must use https (or http to localhost)");
            }
        }
        _ => anyhow::bail!("unsupported scheme"),
    }
    if !u.username().is_empty() || u.password().is_some() {
        anyhow::bail!("userinfo not allowed");
    }
    if u.fragment().is_some() {
        anyhow::bail!("fragment not allowed");
    }
    Ok(raw)
}

fn truncate_err(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}
