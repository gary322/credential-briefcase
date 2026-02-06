//! TPM2-backed key backend (Linux).
//!
//! This backend shells out to `tpm2-tools` so we can validate key creation + signing against
//! `swtpm` in CI without pulling in unstable FFI bindings. It is intentionally conservative:
//! - keys are referenced by **persistent TPM handles**
//! - signatures are converted to JWS-compatible raw `(r||s)` for ES256
//!
//! Requirements:
//! - `tpm2_createprimary`, `tpm2_evictcontrol`, `tpm2_readpublic`, `tpm2_sign` available in `PATH`
//! - caller provides a `TPM2TOOLS_TCTI` string (stored in the key metadata)

use std::process::Command;
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use base64::Engine as _;
use briefcase_core::Sensitive;
use briefcase_secrets::SecretStore;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use tokio::task::{JoinError, spawn_blocking};
use uuid::Uuid;

use crate::{KeyAlgorithm, KeyBackendKind, KeyHandle, KeysError, Signer};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Tpm2KeyMeta {
    tcti: String,
    persistent_handle: u32,
}

#[derive(Clone)]
pub struct Tpm2KeyManager {
    secrets: Arc<dyn SecretStore>,
}

impl Tpm2KeyManager {
    pub fn new(secrets: Arc<dyn SecretStore>) -> Self {
        Self { secrets }
    }

    pub async fn generate_p256(&self, tcti: String) -> anyhow::Result<KeyHandle> {
        let id = Uuid::new_v4().to_string();

        let persistent_handle = derive_persistent_handle(&id);
        let meta = Tpm2KeyMeta {
            tcti,
            persistent_handle,
        };

        create_persistent_p256_signing_key(&meta).await?;

        self.secrets
            .put(
                &meta_secret_id(&id),
                Sensitive(serde_json::to_vec(&meta).context("serialize tpm2 meta")?),
            )
            .await
            .context("store tpm2 meta")?;

        Ok(KeyHandle::new(id, KeyAlgorithm::P256, KeyBackendKind::Tpm2))
    }

    pub fn signer(&self, handle: KeyHandle) -> Arc<dyn Signer> {
        Arc::new(Tpm2Signer {
            secrets: self.secrets.clone(),
            handle,
        })
    }

    pub async fn delete(&self, handle: &KeyHandle) -> anyhow::Result<()> {
        if handle.backend != KeyBackendKind::Tpm2 {
            anyhow::bail!(KeysError::InvalidHandle);
        }

        let meta = self.load_meta(&handle.id).await?;
        let _ = delete_persistent_key(&meta).await;

        let _ = self.secrets.delete(&meta_secret_id(&handle.id)).await;
        Ok(())
    }

    async fn load_meta(&self, id: &str) -> anyhow::Result<Tpm2KeyMeta> {
        let Some(raw) = self
            .secrets
            .get(&meta_secret_id(id))
            .await
            .context("load tpm2 meta")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        serde_json::from_slice(&raw.into_inner()).context("decode tpm2 meta")
    }
}

struct Tpm2Signer {
    secrets: Arc<dyn SecretStore>,
    handle: KeyHandle,
}

impl Tpm2Signer {
    async fn load_meta(&self) -> anyhow::Result<Tpm2KeyMeta> {
        let Some(raw) = self
            .secrets
            .get(&meta_secret_id(&self.handle.id))
            .await
            .context("load tpm2 meta")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        serde_json::from_slice(&raw.into_inner()).context("decode tpm2 meta")
    }
}

#[async_trait]
impl Signer for Tpm2Signer {
    fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    async fn public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        if self.handle.algorithm != KeyAlgorithm::P256
            || self.handle.backend != KeyBackendKind::Tpm2
        {
            anyhow::bail!(KeysError::InvalidHandle);
        }

        let meta = self.load_meta().await?;
        spawn_blocking(move || public_key_bytes_blocking(&meta))
            .await
            .map_err(join_err)?
    }

    async fn public_jwk(&self) -> anyhow::Result<serde_json::Value> {
        let pk = self.public_key_bytes().await?;
        let point = p256::EncodedPoint::from_bytes(&pk).context("decode p256 point")?;
        let x = point.x().context("p256 missing x")?;
        let y = point.y().context("p256 missing y")?;
        Ok(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y),
        }))
    }

    async fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.handle.algorithm != KeyAlgorithm::P256
            || self.handle.backend != KeyBackendKind::Tpm2
        {
            anyhow::bail!(KeysError::InvalidHandle);
        }

        let meta = self.load_meta().await?;
        let msg = msg.to_vec();

        spawn_blocking(move || sign_p256_blocking(&meta, &msg))
            .await
            .map_err(join_err)?
    }
}

fn join_err(e: JoinError) -> anyhow::Error {
    anyhow::anyhow!("tpm2 task join error: {e}")
}

fn meta_secret_id(id: &str) -> String {
    format!("keys.tpm2.{id}.meta")
}

fn derive_persistent_handle(id: &str) -> u32 {
    // Persistent handle range is 0x81000000 - 0x81FFFFFF.
    let digest = sha2::Sha256::digest(id.as_bytes());
    let mut v = u32::from_be_bytes(digest[0..4].try_into().expect("4 bytes"));
    v &= 0x00FF_FFFF;
    if v == 0 {
        v = 1;
    }
    0x8100_0000 | v
}

async fn create_persistent_p256_signing_key(meta: &Tpm2KeyMeta) -> anyhow::Result<()> {
    let meta = meta.clone();
    spawn_blocking(move || create_persistent_p256_signing_key_blocking(&meta))
        .await
        .map_err(join_err)?
}

fn create_persistent_p256_signing_key_blocking(meta: &Tpm2KeyMeta) -> anyhow::Result<()> {
    let handle = fmt_handle(meta.persistent_handle);

    // Create a primary signing key and persist it. This keeps the loaded-object footprint minimal,
    // which is important for some `swtpm` configurations.
    let tmp = tempfile::tempdir().context("create temp dir")?;
    let ctx_path = tmp.path().join("primary.ctx");

    run(
        meta,
        "tpm2_createprimary",
        &[
            "-C",
            "o",
            "-G",
            "ecc",
            "-a",
            "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
            "-c",
            ctx_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("ctx path not utf-8"))?,
        ],
    )
    .context("tpm2_createprimary")?;

    run(
        meta,
        "tpm2_evictcontrol",
        &[
            "-C",
            "o",
            "-c",
            ctx_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("ctx path not utf-8"))?,
            &handle,
        ],
    )
    .context("tpm2_evictcontrol persist")?;

    Ok(())
}

async fn delete_persistent_key(meta: &Tpm2KeyMeta) -> anyhow::Result<()> {
    let meta = meta.clone();
    spawn_blocking(move || delete_persistent_key_blocking(&meta))
        .await
        .map_err(join_err)?
}

fn delete_persistent_key_blocking(meta: &Tpm2KeyMeta) -> anyhow::Result<()> {
    let handle = fmt_handle(meta.persistent_handle);
    run(meta, "tpm2_evictcontrol", &["-C", "o", "-c", &handle])
        .context("tpm2_evictcontrol evict")?;
    Ok(())
}

fn public_key_bytes_blocking(meta: &Tpm2KeyMeta) -> anyhow::Result<Vec<u8>> {
    let handle = fmt_handle(meta.persistent_handle);
    let out = run(meta, "tpm2_readpublic", &["-c", &handle]).context("tpm2_readpublic")?;

    // Parse `x:` and `y:` lines from the tool output.
    let mut x_hex: Option<String> = None;
    let mut y_hex: Option<String> = None;
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("x:") {
            x_hex = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("y:") {
            y_hex = Some(rest.trim().to_string());
        }
    }

    let x = hex::decode(x_hex.ok_or_else(|| anyhow::anyhow!("missing x"))?).context("hex x")?;
    let y = hex::decode(y_hex.ok_or_else(|| anyhow::anyhow!("missing y"))?).context("hex y")?;

    if x.len() != 32 || y.len() != 32 {
        anyhow::bail!(
            "unexpected P-256 public key size x={}, y={}",
            x.len(),
            y.len()
        );
    }

    let mut out = Vec::with_capacity(65);
    out.push(0x04);
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    Ok(out)
}

fn sign_p256_blocking(meta: &Tpm2KeyMeta, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    let handle = fmt_handle(meta.persistent_handle);
    let digest = sha2::Sha256::digest(msg);

    let tmp = tempfile::tempdir().context("create temp dir")?;
    let digest_path = tmp.path().join("digest.bin");
    let sig_path = tmp.path().join("sig.bin");

    std::fs::write(&digest_path, digest).context("write digest")?;

    run(
        meta,
        "tpm2_sign",
        &[
            "-c",
            &handle,
            "-g",
            "sha256",
            "-d",
            "-f",
            "plain",
            "-o",
            sig_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("sig path not utf-8"))?,
            digest_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("digest path not utf-8"))?,
        ],
    )
    .context("tpm2_sign")?;

    let der = std::fs::read(&sig_path).context("read signature")?;
    let sig = p256::ecdsa::Signature::from_der(&der).context("parse DER signature")?;
    Ok(sig.to_bytes().to_vec())
}

fn fmt_handle(handle: u32) -> String {
    format!("0x{handle:08x}")
}

fn run(meta: &Tpm2KeyMeta, bin: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(bin)
        .env("TPM2TOOLS_TCTI", &meta.tcti)
        .args(args)
        .output()
        .with_context(|| format!("spawn {bin}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "{bin} failed status={} stdout={} stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
