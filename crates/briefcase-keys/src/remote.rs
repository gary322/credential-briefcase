//! Remote custody signer backend.
//!
//! This is used for enterprise deployments where signing keys live outside the device (e.g.
//! behind a control plane service backed by an HSM/Vault). The device holds only a short-lived or
//! renewable bearer token for the remote signer.

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use base64::Engine as _;
use briefcase_core::Sensitive;
use briefcase_secrets::SecretStore;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{KeyAlgorithm, KeyBackendKind, KeyHandle, KeysError, Signer};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemoteKeyMeta {
    base_url: String,
    device_id: String,
    key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemoteSignerKeyInfo {
    key_id: String,
    algorithm: String,
    public_jwk: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceRemoteSignerResponse {
    signer: RemoteSignerKeyInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemoteSignRequest {
    key_id: String,
    msg_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemoteSignResponse {
    signature_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ErrorResponse {
    code: String,
    message: String,
}

#[derive(Clone)]
pub struct RemoteKeyManager {
    secrets: Arc<dyn SecretStore>,
    http: reqwest::Client,
}

impl RemoteKeyManager {
    pub fn new(secrets: Arc<dyn SecretStore>) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build reqwest client")?;
        Ok(Self { secrets, http })
    }

    pub async fn upsert(
        &self,
        key_id: String,
        algorithm: KeyAlgorithm,
        base_url: String,
        device_id: String,
        bearer_token: Sensitive<String>,
    ) -> anyhow::Result<KeyHandle> {
        if !is_safe_id(&key_id) {
            anyhow::bail!(KeysError::InvalidHandle);
        }
        let base_url = normalize_base_url(&base_url)?;
        let meta = RemoteKeyMeta {
            base_url,
            device_id,
            key_id: key_id.clone(),
        };
        self.secrets
            .put(
                &meta_secret_id(&key_id),
                Sensitive(serde_json::to_vec(&meta).context("serialize remote meta")?),
            )
            .await
            .context("store remote meta")?;
        self.secrets
            .put(
                &token_secret_id(&key_id),
                Sensitive(bearer_token.0.as_bytes().to_vec()),
            )
            .await
            .context("store remote bearer token")?;
        Ok(KeyHandle::new(key_id, algorithm, KeyBackendKind::Remote))
    }

    pub fn signer(&self, handle: KeyHandle) -> Arc<dyn Signer> {
        Arc::new(RemoteSigner {
            secrets: self.secrets.clone(),
            http: self.http.clone(),
            handle,
        })
    }

    pub async fn delete(&self, handle: &KeyHandle) -> anyhow::Result<()> {
        if handle.backend != KeyBackendKind::Remote {
            anyhow::bail!(KeysError::InvalidHandle);
        }
        let _ = self.secrets.delete(&meta_secret_id(&handle.id)).await;
        let _ = self.secrets.delete(&token_secret_id(&handle.id)).await;
        Ok(())
    }
}

struct RemoteSigner {
    secrets: Arc<dyn SecretStore>,
    http: reqwest::Client,
    handle: KeyHandle,
}

impl RemoteSigner {
    async fn load_meta(&self) -> anyhow::Result<RemoteKeyMeta> {
        let Some(raw) = self
            .secrets
            .get(&meta_secret_id(&self.handle.id))
            .await
            .context("load remote meta")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        let meta: RemoteKeyMeta =
            serde_json::from_slice(&raw.into_inner()).context("decode remote meta")?;
        Ok(meta)
    }

    async fn load_token(&self) -> anyhow::Result<String> {
        let Some(raw) = self
            .secrets
            .get(&token_secret_id(&self.handle.id))
            .await
            .context("load remote token")?
        else {
            anyhow::bail!(KeysError::UnknownKey);
        };
        String::from_utf8(raw.into_inner()).context("remote token is not utf-8")
    }

    async fn get_key_info(
        &self,
        meta: &RemoteKeyMeta,
        token: &str,
    ) -> anyhow::Result<RemoteSignerKeyInfo> {
        let url = Url::parse(&meta.base_url)
            .context("parse base_url")?
            .join(&format!("/v1/devices/{}/remote-signer", meta.device_id))
            .context("join remote signer url")?;
        let resp = self
            .http
            .get(url)
            .header("accept", "application/json")
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .context("send remote signer request")?;

        parse_json_response::<DeviceRemoteSignerResponse>(resp)
            .await
            .map(|r| r.signer)
    }
}

#[async_trait]
impl Signer for RemoteSigner {
    fn handle(&self) -> &KeyHandle {
        &self.handle
    }

    async fn public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let meta = self.load_meta().await?;
        let token = self.load_token().await?;
        let info = self.get_key_info(&meta, &token).await?;
        self.public_key_bytes_from_jwk(&info.public_jwk)
    }

    async fn public_jwk(&self) -> anyhow::Result<serde_json::Value> {
        let meta = self.load_meta().await?;
        let token = self.load_token().await?;
        let info = self.get_key_info(&meta, &token).await?;
        Ok(info.public_jwk)
    }

    async fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let meta = self.load_meta().await?;
        let token = self.load_token().await?;

        let url = Url::parse(&meta.base_url)
            .context("parse base_url")?
            .join(&format!(
                "/v1/devices/{}/remote-signer/sign",
                meta.device_id
            ))
            .context("join remote sign url")?;

        let msg_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(msg);
        let resp = self
            .http
            .post(url)
            .header("accept", "application/json")
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            .json(&RemoteSignRequest {
                key_id: meta.key_id.clone(),
                msg_b64,
            })
            .send()
            .await
            .context("send remote sign request")?;

        let out = parse_json_response::<RemoteSignResponse>(resp).await?;
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(out.signature_b64.as_bytes())
            .context("decode signature_b64")?;

        match self.handle.algorithm {
            KeyAlgorithm::Ed25519 => {
                if sig.len() != 64 {
                    anyhow::bail!(KeysError::Backend(
                        "ed25519 signature wrong length".to_string()
                    ));
                }
            }
            KeyAlgorithm::P256 => {
                if sig.len() != 64 {
                    anyhow::bail!(KeysError::Backend(
                        "p256 signature wrong length".to_string()
                    ));
                }
            }
        }

        Ok(sig)
    }
}

impl RemoteSigner {
    fn public_key_bytes_from_jwk(&self, jwk: &serde_json::Value) -> anyhow::Result<Vec<u8>> {
        match self.handle.algorithm {
            KeyAlgorithm::Ed25519 => {
                let obj = jwk.as_object().context("jwk must be object")?;
                let x_b64 = obj
                    .get("x")
                    .and_then(|v| v.as_str())
                    .context("missing jwk.x")?;
                let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x_b64.as_bytes())
                    .context("decode jwk.x")?;
                if x.len() != 32 {
                    anyhow::bail!(KeysError::Backend(
                        "ed25519 pubkey wrong length".to_string()
                    ));
                }
                Ok(x)
            }
            KeyAlgorithm::P256 => {
                let obj = jwk.as_object().context("jwk must be object")?;
                let x_b64 = obj
                    .get("x")
                    .and_then(|v| v.as_str())
                    .context("missing jwk.x")?;
                let y_b64 = obj
                    .get("y")
                    .and_then(|v| v.as_str())
                    .context("missing jwk.y")?;
                let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x_b64.as_bytes())
                    .context("decode jwk.x")?;
                let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(y_b64.as_bytes())
                    .context("decode jwk.y")?;
                if x.len() != 32 || y.len() != 32 {
                    anyhow::bail!(KeysError::Backend(
                        "p256 coordinate wrong length".to_string()
                    ));
                }
                let mut out = Vec::with_capacity(65);
                out.push(0x04);
                out.extend_from_slice(&x);
                out.extend_from_slice(&y);
                Ok(out)
            }
        }
    }
}

fn meta_secret_id(key_id: &str) -> String {
    format!("keys.remote.{key_id}.meta")
}

fn token_secret_id(key_id: &str) -> String {
    format!("keys.remote.{key_id}.bearer_token")
}

fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':')
}

fn normalize_base_url(base_url: &str) -> anyhow::Result<String> {
    let raw = base_url.trim().trim_end_matches('/').to_string();
    let u = Url::parse(&raw).context("parse base_url")?;
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
                anyhow::bail!("remote signer must use https (or http to localhost)");
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

async fn parse_json_response<T: for<'de> Deserialize<'de>>(
    resp: reqwest::Response,
) -> anyhow::Result<T> {
    let status = resp.status();
    let bytes = resp.bytes().await.context("read response bytes")?;
    if !status.is_success() {
        if let Ok(err) = serde_json::from_slice::<ErrorResponse>(&bytes) {
            anyhow::bail!("remote signer error {}: {}", err.code, err.message);
        }
        anyhow::bail!(
            "remote signer http error {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    serde_json::from_slice::<T>(&bytes).context("decode response json")
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature as P256Sig, SigningKey as P256Sk, VerifyingKey as P256Vk};
    use tokio::sync::Mutex;

    #[derive(Clone)]
    struct MockState {
        token: String,
        device_id: String,
        key_id: String,
        sk: Arc<Mutex<P256Sk>>,
    }

    async fn require_bearer(headers: &HeaderMap, want: &str) -> bool {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t == want)
            .unwrap_or(false)
    }

    async fn get_remote_signer(
        State(st): State<MockState>,
        Path(device_id): Path<String>,
        headers: HeaderMap,
    ) -> Result<Json<DeviceRemoteSignerResponse>, StatusCode> {
        if !require_bearer(&headers, &st.token).await || device_id != st.device_id {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let sk = st.sk.lock().await;
        let vk = sk.verifying_key();
        let jwk = {
            let point = vk.to_encoded_point(false);
            let x = point.x().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
            let y = point.y().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
            serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
                "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y),
            })
        };
        Ok(Json(DeviceRemoteSignerResponse {
            signer: RemoteSignerKeyInfo {
                key_id: st.key_id.clone(),
                algorithm: "p256".to_string(),
                public_jwk: jwk,
            },
        }))
    }

    async fn post_sign(
        State(st): State<MockState>,
        Path(device_id): Path<String>,
        headers: HeaderMap,
        Json(req): Json<RemoteSignRequest>,
    ) -> Result<Json<RemoteSignResponse>, StatusCode> {
        if !require_bearer(&headers, &st.token).await || device_id != st.device_id {
            return Err(StatusCode::UNAUTHORIZED);
        }
        if req.key_id != st.key_id {
            return Err(StatusCode::BAD_REQUEST);
        }
        let msg = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(req.msg_b64.as_bytes())
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let sk = st.sk.lock().await;
        let sig: P256Sig = sk.sign(&msg);
        Ok(Json(RemoteSignResponse {
            signature_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        }))
    }

    #[tokio::test]
    async fn remote_signer_public_key_and_signing_work() -> anyhow::Result<()> {
        use p256::ecdsa::signature::Verifier as _;

        let token = "tok";
        let device_id = "00000000-0000-0000-0000-000000000001";
        let key_id = "k1";

        let sk = P256Sk::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let st = MockState {
            token: token.to_string(),
            device_id: device_id.to_string(),
            key_id: key_id.to_string(),
            sk: Arc::new(Mutex::new(sk)),
        };

        let app = Router::new()
            .route("/v1/devices/{id}/remote-signer", get(get_remote_signer))
            .route("/v1/devices/{id}/remote-signer/sign", post(post_sign))
            .with_state(st.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let secrets = Arc::new(briefcase_secrets::InMemorySecretStore::default());
        let km = RemoteKeyManager::new(secrets.clone())?;
        let handle = km
            .upsert(
                key_id.to_string(),
                KeyAlgorithm::P256,
                format!("http://{addr}"),
                device_id.to_string(),
                Sensitive(token.to_string()),
            )
            .await?;

        let signer = km.signer(handle);
        let pub_bytes = signer.public_key_bytes().await?;
        let vk = P256Vk::from_sec1_bytes(&pub_bytes).context("decode p256 pubkey")?;
        let sig_bytes = signer.sign(b"hello").await?;
        let sig = P256Sig::from_slice(&sig_bytes).context("parse signature")?;
        vk.verify(b"hello", &sig)?;

        task.abort();
        Ok(())
    }
}
