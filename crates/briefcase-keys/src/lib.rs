//! Key custody and signing abstraction for the Briefcase.
//!
//! Security goals:
//! - callers operate on **handles**, not raw private key bytes
//! - software backend stores private material only in `briefcase-secrets`
//! - future backends (TPM/HSM/Secure Enclave) can keep keys non-exportable

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

#[cfg(feature = "tpm2")]
pub mod tpm2;

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use base64::Engine as _;
use briefcase_core::Sensitive;
use briefcase_secrets::SecretStore;
use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum KeysError {
    #[error("unknown key")]
    UnknownKey,
    #[error("invalid key handle")]
    InvalidHandle,
    #[error("backend error: {0}")]
    Backend(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    Ed25519,
    P256,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackendKind {
    Software,
    // Placeholders for Phase 4.x backends.
    Pkcs11,
    Tpm2,
    Apple,
    Windows,
    Remote,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyHandle {
    pub id: String,
    pub algorithm: KeyAlgorithm,
    pub backend: KeyBackendKind,
}

impl KeyHandle {
    pub fn new(id: impl Into<String>, algorithm: KeyAlgorithm, backend: KeyBackendKind) -> Self {
        Self {
            id: id.into(),
            algorithm,
            backend,
        }
    }

    pub fn to_json(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(self).context("serialize key handle")
    }

    pub fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(bytes).context("deserialize key handle")
    }
}

#[async_trait]
pub trait Signer: Send + Sync {
    fn handle(&self) -> &KeyHandle;

    async fn public_key_bytes(&self) -> anyhow::Result<Vec<u8>>;
    async fn public_jwk(&self) -> anyhow::Result<serde_json::Value>;

    async fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>>;
}

#[derive(Clone)]
pub struct SoftwareKeyManager {
    secrets: Arc<dyn SecretStore>,
}

impl SoftwareKeyManager {
    pub fn new(secrets: Arc<dyn SecretStore>) -> Self {
        Self { secrets }
    }

    pub async fn generate(&self, algorithm: KeyAlgorithm) -> anyhow::Result<KeyHandle> {
        match algorithm {
            KeyAlgorithm::Ed25519 => {
                let mut seed = [0u8; 32];
                rand::rng().fill_bytes(&mut seed);
                self.import_ed25519_seed(seed).await
            }
            KeyAlgorithm::P256 => {
                use p256::pkcs8::EncodePrivateKey as _;
                let id = Uuid::new_v4().to_string();
                let signing = P256SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
                let pkcs8 = signing.to_pkcs8_der().context("encode p256 key as pkcs8")?;
                self.secrets
                    .put(
                        &secret_id_for(&id, KeyAlgorithm::P256),
                        Sensitive(pkcs8.as_bytes().to_vec()),
                    )
                    .await
                    .context("store p256 secret")?;
                Ok(KeyHandle::new(
                    id,
                    KeyAlgorithm::P256,
                    KeyBackendKind::Software,
                ))
            }
        }
    }

    pub async fn import_ed25519_seed(&self, seed: [u8; 32]) -> anyhow::Result<KeyHandle> {
        let id = Uuid::new_v4().to_string();
        self.secrets
            .put(
                &secret_id_for(&id, KeyAlgorithm::Ed25519),
                Sensitive(seed.to_vec()),
            )
            .await
            .context("store ed25519 seed")?;
        Ok(KeyHandle::new(
            id,
            KeyAlgorithm::Ed25519,
            KeyBackendKind::Software,
        ))
    }

    pub fn signer(&self, handle: KeyHandle) -> Arc<dyn Signer> {
        Arc::new(SoftwareSigner {
            secrets: self.secrets.clone(),
            handle,
        })
    }

    pub async fn delete(&self, handle: &KeyHandle) -> anyhow::Result<()> {
        self.secrets
            .delete(&secret_id_for(&handle.id, handle.algorithm.clone()))
            .await
            .context("delete key secret")?;
        Ok(())
    }
}

struct SoftwareSigner {
    secrets: Arc<dyn SecretStore>,
    handle: KeyHandle,
}

impl SoftwareSigner {
    async fn load_secret(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let Some(v) = self
            .secrets
            .get(&secret_id_for(
                &self.handle.id,
                self.handle.algorithm.clone(),
            ))
            .await
            .context("load key secret")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        Ok(Zeroizing::new(v.into_inner()))
    }
}

#[async_trait]
impl Signer for SoftwareSigner {
    fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    async fn public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        match self.handle.algorithm {
            KeyAlgorithm::Ed25519 => {
                let sk = self.load_secret().await?;
                if sk.len() != 32 {
                    anyhow::bail!(KeysError::Backend("ed25519 seed wrong length".to_string()));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&sk);
                let signing = Ed25519SigningKey::from_bytes(&seed);
                Ok(signing.verifying_key().as_bytes().to_vec())
            }
            KeyAlgorithm::P256 => {
                use p256::pkcs8::DecodePrivateKey as _;
                let der = self.load_secret().await?;
                let signing = P256SigningKey::from_pkcs8_der(&der).context("decode p256 pkcs8")?;
                let verifying = signing.verifying_key();
                let point = verifying.to_encoded_point(false);
                Ok(point.as_bytes().to_vec())
            }
        }
    }

    async fn public_jwk(&self) -> anyhow::Result<serde_json::Value> {
        match self.handle.algorithm {
            KeyAlgorithm::Ed25519 => {
                let pk = self.public_key_bytes().await?;
                if pk.len() != 32 {
                    anyhow::bail!(KeysError::Backend(
                        "ed25519 pubkey wrong length".to_string()
                    ));
                }
                let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk);
                Ok(serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": x,
                }))
            }
            KeyAlgorithm::P256 => {
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
        }
    }

    async fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.handle.algorithm {
            KeyAlgorithm::Ed25519 => {
                let sk = self.load_secret().await?;
                if sk.len() != 32 {
                    anyhow::bail!(KeysError::Backend("ed25519 seed wrong length".to_string()));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&sk);
                let signing = Ed25519SigningKey::from_bytes(&seed);
                let sig: Ed25519Signature = signing.sign(msg);
                Ok(sig.to_bytes().to_vec())
            }
            KeyAlgorithm::P256 => {
                use p256::pkcs8::DecodePrivateKey as _;
                let der = self.load_secret().await?;
                let signing = P256SigningKey::from_pkcs8_der(&der).context("decode p256 pkcs8")?;
                let sig: P256Signature = signing.sign(msg);
                Ok(sig.to_bytes().to_vec())
            }
        }
    }
}

fn secret_id_for(id: &str, alg: KeyAlgorithm) -> String {
    match alg {
        KeyAlgorithm::Ed25519 => format!("keys.software.{id}.ed25519_seed"),
        KeyAlgorithm::P256 => format!("keys.software.{id}.p256_pkcs8"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn software_ed25519_round_trips() -> anyhow::Result<()> {
        let secrets = Arc::new(briefcase_secrets::InMemorySecretStore::default());
        let km = SoftwareKeyManager::new(secrets);
        let handle = km.generate(KeyAlgorithm::Ed25519).await?;
        let signer = km.signer(handle.clone());

        let pk = signer.public_key_bytes().await?;
        assert_eq!(pk.len(), 32);
        let jwk = signer.public_jwk().await?;
        assert_eq!(jwk.get("kty").and_then(|v| v.as_str()), Some("OKP"));

        let sig = signer.sign(b"hello").await?;
        assert_eq!(sig.len(), 64);

        km.delete(&handle).await?;
        Ok(())
    }

    #[tokio::test]
    async fn software_p256_round_trips() -> anyhow::Result<()> {
        let secrets = Arc::new(briefcase_secrets::InMemorySecretStore::default());
        let km = SoftwareKeyManager::new(secrets);
        let handle = km.generate(KeyAlgorithm::P256).await?;
        let signer = km.signer(handle.clone());

        let pk = signer.public_key_bytes().await?;
        assert!(!pk.is_empty());
        let jwk = signer.public_jwk().await?;
        assert_eq!(jwk.get("kty").and_then(|v| v.as_str()), Some("EC"));

        let sig = signer.sign(b"hello").await?;
        assert_eq!(sig.len(), 64);

        km.delete(&handle).await?;
        Ok(())
    }
}
