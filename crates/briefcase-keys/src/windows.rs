//! Windows CNG/NCrypt-backed key backend.
//!
//! This backend uses the Windows CNG Key Storage Providers (KSP) via `ncrypt.dll`.
//! It prefers TPM-backed key storage (Microsoft Platform Crypto Provider) when available,
//! and falls back to the Software KSP otherwise.
//!
//! Design:
//! - The `KeyHandle` is an opaque id.
//! - Key material never leaves the KSP; we persist only `(provider, key_name)` metadata.
//! - Signatures are returned in JWS-friendly raw `(r||s)` format for ES256.

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
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, MS_KEY_STORAGE_PROVIDER,
    MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_EXPORT_POLICY_PROPERTY,
    NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY,
    NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey,
    NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
};
use windows_sys::core::HRESULT;

use crate::{KeyAlgorithm, KeyBackendKind, KeyHandle, KeysError, Signer};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WindowsKeyMeta {
    provider: String,
    key_name: String,
    tpm: bool,
}

#[derive(Clone)]
pub struct WindowsKeyManager {
    secrets: Arc<dyn SecretStore>,
}

impl WindowsKeyManager {
    pub fn new(secrets: Arc<dyn SecretStore>) -> Self {
        Self { secrets }
    }

    pub async fn generate_p256(&self) -> anyhow::Result<KeyHandle> {
        let id = Uuid::new_v4().to_string();
        let key_name = format!("briefcase-{id}");

        let meta = spawn_blocking({
            let key_name = key_name.clone();
            move || create_p256_key_blocking(&key_name)
        })
        .await
        .map_err(join_err)??;

        // Persist metadata after the key exists; if we fail to write metadata, delete the key.
        if let Err(e) = self
            .secrets
            .put(
                &meta_secret_id(&id),
                Sensitive(serde_json::to_vec(&meta).context("serialize windows key meta")?),
            )
            .await
        {
            let _ = spawn_blocking({
                let meta = meta.clone();
                move || delete_key_by_meta_blocking(&meta)
            })
            .await;
            return Err(anyhow::Error::new(e)).context("store windows key meta");
        }

        Ok(KeyHandle::new(
            id,
            KeyAlgorithm::P256,
            KeyBackendKind::Windows,
        ))
    }

    pub fn signer(&self, handle: KeyHandle) -> Arc<dyn Signer> {
        Arc::new(WindowsSigner {
            secrets: self.secrets.clone(),
            handle,
        })
    }

    pub async fn delete(&self, handle: &KeyHandle) -> anyhow::Result<()> {
        if handle.backend != KeyBackendKind::Windows {
            anyhow::bail!(KeysError::InvalidHandle);
        }

        let meta = self.load_meta(&handle.id).await?;
        let _ = spawn_blocking(move || delete_key_by_meta_blocking(&meta))
            .await
            .map_err(join_err)?;

        let _ = self.secrets.delete(&meta_secret_id(&handle.id)).await;
        Ok(())
    }

    async fn load_meta(&self, id: &str) -> anyhow::Result<WindowsKeyMeta> {
        let Some(raw) = self
            .secrets
            .get(&meta_secret_id(id))
            .await
            .context("load windows meta")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        serde_json::from_slice(&raw.into_inner()).context("decode windows meta")
    }
}

struct WindowsSigner {
    secrets: Arc<dyn SecretStore>,
    handle: KeyHandle,
}

impl WindowsSigner {
    async fn load_meta(&self) -> anyhow::Result<WindowsKeyMeta> {
        let Some(raw) = self
            .secrets
            .get(&meta_secret_id(&self.handle.id))
            .await
            .context("load windows meta")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        serde_json::from_slice(&raw.into_inner()).context("decode windows meta")
    }
}

#[async_trait]
impl Signer for WindowsSigner {
    fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    async fn public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        if self.handle.algorithm != KeyAlgorithm::P256
            || self.handle.backend != KeyBackendKind::Windows
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
            || self.handle.backend != KeyBackendKind::Windows
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
    anyhow::anyhow!("windows task join error: {e}")
}

fn meta_secret_id(id: &str) -> String {
    format!("keys.windows.{id}.meta")
}

fn hr_ok(hr: HRESULT) -> bool {
    hr >= 0
}

fn hr_bail(hr: HRESULT, what: &str) -> anyhow::Error {
    anyhow::anyhow!("{what} failed (HRESULT=0x{hr:08x})")
}

fn wide_null(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

#[derive(Debug)]
struct NcryptObject(NCRYPT_HANDLE);

impl Drop for NcryptObject {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

fn open_provider_blocking(
    provider: *const u16,
) -> anyhow::Result<(NCRYPT_PROV_HANDLE, NcryptObject)> {
    let mut h: NCRYPT_PROV_HANDLE = 0;
    let hr = unsafe { NCryptOpenStorageProvider(&mut h, provider, NCRYPT_SILENT_FLAG) };
    if !hr_ok(hr) {
        return Err(hr_bail(hr, "NCryptOpenStorageProvider"));
    }
    Ok((h, NcryptObject(h as NCRYPT_HANDLE)))
}

fn open_key_blocking(
    prov: NCRYPT_PROV_HANDLE,
    key_name: &str,
) -> anyhow::Result<(NCRYPT_KEY_HANDLE, NcryptObject)> {
    let mut h: NCRYPT_KEY_HANDLE = 0;
    let name_w = wide_null(key_name);
    let hr = unsafe { NCryptOpenKey(prov, &mut h, name_w.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
    if !hr_ok(hr) {
        return Err(hr_bail(hr, "NCryptOpenKey"));
    }
    Ok((h, NcryptObject(h as NCRYPT_HANDLE)))
}

fn create_p256_key_blocking(key_name: &str) -> anyhow::Result<WindowsKeyMeta> {
    // Prefer TPM provider if available.
    let (prov_name, tpm, (prov, _prov_guard)) =
        match open_provider_blocking(MS_PLATFORM_CRYPTO_PROVIDER) {
            Ok(v) => ("Microsoft Platform Crypto Provider".to_string(), true, v),
            Err(_) => (
                "Microsoft Software Key Storage Provider".to_string(),
                false,
                open_provider_blocking(MS_KEY_STORAGE_PROVIDER)?,
            ),
        };

    let mut key: NCRYPT_KEY_HANDLE = 0;
    let key_name_w = wide_null(key_name);

    let flags: NCRYPT_FLAGS = NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_SILENT_FLAG;
    let hr = unsafe {
        NCryptCreatePersistedKey(
            prov,
            &mut key,
            NCRYPT_ECDSA_P256_ALGORITHM,
            key_name_w.as_ptr(),
            0,
            flags,
        )
    };
    if !hr_ok(hr) {
        return Err(hr_bail(hr, "NCryptCreatePersistedKey"));
    }
    let _key_guard = NcryptObject(key as NCRYPT_HANDLE);

    // Try to make key non-exportable (public export is still supported).
    let export_policy: u32 = 0;
    let hr = unsafe {
        NCryptSetProperty(
            key as NCRYPT_HANDLE,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            (&export_policy as *const u32).cast(),
            std::mem::size_of_val(&export_policy) as u32,
            0,
        )
    };
    if !hr_ok(hr) {
        // Non-fatal: some providers reject this property; key is still non-exportable by default.
    }

    let len: u32 = 256;
    let hr = unsafe {
        NCryptSetProperty(
            key as NCRYPT_HANDLE,
            NCRYPT_LENGTH_PROPERTY,
            (&len as *const u32).cast(),
            std::mem::size_of_val(&len) as u32,
            0,
        )
    };
    if !hr_ok(hr) {
        // Non-fatal: algorithm already implies key size.
    }

    let hr = unsafe { NCryptFinalizeKey(key, 0) };
    if !hr_ok(hr) {
        return Err(hr_bail(hr, "NCryptFinalizeKey"));
    }

    Ok(WindowsKeyMeta {
        provider: prov_name,
        key_name: key_name.to_string(),
        tpm,
    })
}

fn provider_pcwstr(meta: &WindowsKeyMeta) -> *const u16 {
    if meta.tpm {
        MS_PLATFORM_CRYPTO_PROVIDER
    } else {
        MS_KEY_STORAGE_PROVIDER
    }
}

fn export_public_key_blob_blocking(meta: &WindowsKeyMeta) -> anyhow::Result<Vec<u8>> {
    let (prov, _prov_guard) = open_provider_blocking(provider_pcwstr(meta))?;
    let (key, _key_guard) = open_key_blocking(prov, &meta.key_name)?;

    let mut needed: u32 = 0;
    let hr = unsafe {
        NCryptExportKey(
            key,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            &mut needed,
            0,
        )
    };
    if !hr_ok(hr) {
        return Err(hr_bail(hr, "NCryptExportKey (size)"));
    }

    let mut buf = vec![0u8; needed as usize];
    let hr = unsafe {
        NCryptExportKey(
            key,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            std::ptr::null(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut needed,
            0,
        )
    };
    if !hr_ok(hr) {
        return Err(hr_bail(hr, "NCryptExportKey"));
    }
    buf.truncate(needed as usize);
    Ok(buf)
}

fn public_key_bytes_blocking(meta: &WindowsKeyMeta) -> anyhow::Result<Vec<u8>> {
    let blob = export_public_key_blob_blocking(meta)?;

    // Parse BCRYPT_ECCKEY_BLOB (little-endian fields).
    if blob.len() < 8 {
        anyhow::bail!("ecc public blob too small");
    }
    let magic = u32::from_le_bytes(blob[0..4].try_into().expect("4 bytes"));
    let cb_key = u32::from_le_bytes(blob[4..8].try_into().expect("4 bytes")) as usize;

    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC {
        anyhow::bail!("unexpected ecc magic: {magic}");
    }
    if cb_key != 32 {
        anyhow::bail!("unexpected p256 cbKey: {cb_key}");
    }

    let expected = 8 + (2 * cb_key);
    if blob.len() != expected {
        anyhow::bail!("unexpected ecc public blob size: {}", blob.len());
    }

    let x = &blob[8..8 + cb_key];
    let y = &blob[8 + cb_key..8 + (2 * cb_key)];

    let mut out = Vec::with_capacity(65);
    out.push(0x04);
    out.extend_from_slice(x);
    out.extend_from_slice(y);
    Ok(out)
}

fn sign_p256_blocking(meta: &WindowsKeyMeta, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (prov, _prov_guard) = open_provider_blocking(provider_pcwstr(meta))?;
    let (key, _key_guard) = open_key_blocking(prov, &meta.key_name)?;

    let digest = sha2::Sha256::digest(msg);

    let mut needed: u32 = 0;
    let hr = unsafe {
        NCryptSignHash(
            key,
            std::ptr::null(),
            digest.as_ptr(),
            digest.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut needed,
            0,
        )
    };
    if !hr_ok(hr) {
        return Err(hr_bail(hr, "NCryptSignHash (size)"));
    }

    let mut sig = vec![0u8; needed as usize];
    let hr = unsafe {
        NCryptSignHash(
            key,
            std::ptr::null(),
            digest.as_ptr(),
            digest.len() as u32,
            sig.as_mut_ptr(),
            sig.len() as u32,
            &mut needed,
            0,
        )
    };
    if !hr_ok(hr) {
        return Err(hr_bail(hr, "NCryptSignHash"));
    }
    sig.truncate(needed as usize);

    if sig.len() != 64 {
        anyhow::bail!("unexpected p256 signature size: {}", sig.len());
    }
    Ok(sig)
}

fn delete_key_by_meta_blocking(meta: &WindowsKeyMeta) -> anyhow::Result<()> {
    let (prov, _prov_guard) = open_provider_blocking(provider_pcwstr(meta))?;
    let (key, _key_guard) = open_key_blocking(prov, &meta.key_name)?;

    let hr = unsafe { NCryptDeleteKey(key, 0) };
    if !hr_ok(hr) {
        return Err(hr_bail(hr, "NCryptDeleteKey"));
    }
    Ok(())
}
