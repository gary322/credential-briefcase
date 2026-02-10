use std::collections::BTreeMap;
use std::net::SocketAddr;

use anyhow::Context as _;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use briefcase_control_plane_api::types::{
    AdminSetPolicyRequest, AdminSetPolicyResponse, AuditListReceiptsResponse, DevicePolicyResponse,
    DeviceRemoteSignerResponse, EnrollDeviceRequest, EnrollDeviceResponse, ErrorResponse,
    HealthResponse, PolicyBundle, RemoteSignRequest, RemoteSignResponse, RemoteSignerKeyInfo,
    SignedPolicyBundle, UploadReceiptsRequest, UploadReceiptsResponse,
};
use briefcase_core::{
    COMPATIBILITY_PROFILE_VERSION,
    util::{sha256_hex, sha256_hex_concat},
};
use chrono::{DateTime, Utc};
use clap::Parser;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use rand::RngCore as _;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use subtle::ConstantTimeEq as _;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use url::Url;
use uuid::Uuid;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:9797";
const MAX_POLICY_TEXT_BYTES: usize = 200_000;
const MAX_RECEIPTS_PER_UPLOAD: usize = 500;
const MAX_REMOTE_SIGN_MSG_BYTES: usize = 32_000;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "briefcase-control-plane",
    version,
    about = "Credential Briefcase control plane (reference)"
)]
struct Args {
    /// Address to bind.
    #[arg(long, env = "CONTROL_PLANE_BIND_ADDR", default_value = DEFAULT_BIND_ADDR)]
    bind_addr: SocketAddr,

    /// Public base URL used for DPoP `htu` verification on device endpoints.
    ///
    /// If unset, defaults to `http://<bind_addr>`.
    #[arg(long, env = "CONTROL_PLANE_PUBLIC_BASE_URL")]
    public_base_url: Option<String>,

    /// Postgres connection string, e.g. `postgres://user:pass@127.0.0.1:5432/db`.
    #[arg(long, env = "CONTROL_PLANE_DATABASE_URL")]
    database_url: String,

    /// Admin bearer token (required).
    #[arg(long, env = "CONTROL_PLANE_ADMIN_TOKEN")]
    admin_token: String,

    /// Auditor bearer token (required). May be the same as admin.
    #[arg(long, env = "CONTROL_PLANE_AUDITOR_TOKEN")]
    auditor_token: String,

    /// Ed25519 signing key seed (32 bytes, base64url; required).
    #[arg(long, env = "CONTROL_PLANE_POLICY_SIGNING_KEY_SEED_B64")]
    policy_signing_key_seed_b64: String,

    /// Remote custody backend for device PoP signing keys: `derived` (default) or `pkcs11`.
    ///
    /// - `derived`: deterministic P-256 key derived from a server seed + device_id.
    /// - `pkcs11`: non-exportable P-256 keys stored in a PKCS#11 token (SoftHSM in CI).
    #[arg(
        long,
        env = "CONTROL_PLANE_REMOTE_SIGNER_BACKEND",
        default_value = "derived"
    )]
    remote_signer_backend: String,

    /// Seed for derived remote signer keys (32 bytes, base64url). If unset, defaults to the policy
    /// signing seed (reference-only; production deployments should use a distinct secret).
    #[arg(long, env = "CONTROL_PLANE_REMOTE_SIGNER_SEED_B64")]
    remote_signer_seed_b64: Option<String>,

    /// PKCS#11 module path (required for `pkcs11` backend). If unset, falls back to
    /// `BRIEFCASE_PKCS11_MODULE` to reuse the repo's SoftHSM harness defaults.
    #[arg(long, env = "CONTROL_PLANE_PKCS11_MODULE")]
    pkcs11_module: Option<String>,

    /// PKCS#11 token label (required for `pkcs11` backend). If unset, falls back to
    /// `BRIEFCASE_PKCS11_TOKEN_LABEL`.
    #[arg(long, env = "CONTROL_PLANE_PKCS11_TOKEN_LABEL")]
    pkcs11_token_label: Option<String>,

    /// PKCS#11 user PIN (required for `pkcs11` backend). If unset, falls back to
    /// `BRIEFCASE_PKCS11_USER_PIN`.
    #[arg(long, env = "CONTROL_PLANE_PKCS11_USER_PIN")]
    pkcs11_user_pin: Option<String>,
}

#[derive(Clone)]
struct AppState {
    pool: PgPool,
    admin_token: String,
    auditor_token: String,
    policy_signer: SigningKey,
    policy_pubkey_b64: String,
    remote_signer: RemoteSignerBackend,
    public_base_url: Url,
}

#[derive(Debug, Clone)]
enum RemoteSignerBackend {
    DerivedP256 {
        seed: [u8; 32],
    },
    #[cfg(feature = "pkcs11")]
    Pkcs11P256 {
        module_path: String,
        token_label: String,
        user_pin: String,
    },
}

fn build_remote_signer_backend(args: &Args) -> anyhow::Result<RemoteSignerBackend> {
    let mode = args.remote_signer_backend.trim().to_lowercase();
    match mode.as_str() {
        "derived" | "derived_p256" => {
            let seed_b64 = args
                .remote_signer_seed_b64
                .as_deref()
                .unwrap_or(&args.policy_signing_key_seed_b64);
            let seed = parse_seed_32_b64url(seed_b64).context("parse remote signer seed")?;
            Ok(RemoteSignerBackend::DerivedP256 { seed })
        }
        "pkcs11" | "pkcs11_p256" => {
            #[cfg(feature = "pkcs11")]
            {
                let module_path = args
                    .pkcs11_module
                    .clone()
                    .or_else(|| std::env::var("BRIEFCASE_PKCS11_MODULE").ok())
                    .context("missing CONTROL_PLANE_PKCS11_MODULE (or BRIEFCASE_PKCS11_MODULE)")?;
                let token_label = args
                    .pkcs11_token_label
                    .clone()
                    .or_else(|| std::env::var("BRIEFCASE_PKCS11_TOKEN_LABEL").ok())
                    .context(
                        "missing CONTROL_PLANE_PKCS11_TOKEN_LABEL (or BRIEFCASE_PKCS11_TOKEN_LABEL)",
                    )?;
                let user_pin = args
                    .pkcs11_user_pin
                    .clone()
                    .or_else(|| std::env::var("BRIEFCASE_PKCS11_USER_PIN").ok())
                    .context(
                        "missing CONTROL_PLANE_PKCS11_USER_PIN (or BRIEFCASE_PKCS11_USER_PIN)",
                    )?;
                Ok(RemoteSignerBackend::Pkcs11P256 {
                    module_path,
                    token_label,
                    user_pin,
                })
            }
            #[cfg(not(feature = "pkcs11"))]
            {
                anyhow::bail!(
                    "remote signer backend `pkcs11` requires building with --features pkcs11"
                );
            }
        }
        other => anyhow::bail!("unsupported CONTROL_PLANE_REMOTE_SIGNER_BACKEND: {other}"),
    }
}

impl RemoteSignerBackend {
    fn key_id_for_device(&self, device_id: Uuid) -> String {
        // Keep v1 simple: one PoP key per device, stable until rotated.
        device_id.to_string()
    }

    async fn key_info(&self, device_id: Uuid) -> anyhow::Result<RemoteSignerKeyInfo> {
        let key_id = self.key_id_for_device(device_id);
        let public_jwk = self.public_jwk(device_id).await?;
        Ok(RemoteSignerKeyInfo {
            key_id,
            algorithm: "p256".to_string(),
            public_jwk,
        })
    }

    async fn public_jwk(&self, device_id: Uuid) -> anyhow::Result<serde_json::Value> {
        match self {
            RemoteSignerBackend::DerivedP256 { seed } => {
                let sk = derive_p256_signing_key(seed, device_id)?;
                let vk = sk.verifying_key();
                p256_public_jwk(vk)
            }
            #[cfg(feature = "pkcs11")]
            RemoteSignerBackend::Pkcs11P256 {
                module_path,
                token_label,
                user_pin,
            } => {
                let key_label = pkcs11_key_label_for_device(device_id);
                let pk = pkcs11::ensure_and_load_public_key_bytes(
                    module_path,
                    token_label,
                    user_pin,
                    &key_label,
                )
                .await?;
                let point = p256::EncodedPoint::from_bytes(&pk).context("decode p256 point")?;
                let vk = P256VerifyingKey::from_encoded_point(&point).context("verifying key")?;
                p256_public_jwk(&vk)
            }
        }
    }

    async fn sign(&self, device_id: Uuid, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            RemoteSignerBackend::DerivedP256 { seed } => {
                let sk = derive_p256_signing_key(seed, device_id)?;
                let sig: P256Signature = sk.sign(msg);
                Ok(sig.to_bytes().to_vec())
            }
            #[cfg(feature = "pkcs11")]
            RemoteSignerBackend::Pkcs11P256 {
                module_path,
                token_label,
                user_pin,
            } => {
                let key_label = pkcs11_key_label_for_device(device_id);
                pkcs11::ensure_and_sign_p256(module_path, token_label, user_pin, &key_label, msg)
                    .await
            }
        }
    }
}

fn parse_seed_32_b64url(b64: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.trim().as_bytes())
        .context("base64url decode")?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32-byte seed");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn derive_p256_signing_key(seed: &[u8; 32], device_id: Uuid) -> anyhow::Result<P256SigningKey> {
    use sha2::Digest as _;

    for ctr in 0u8..=255 {
        let digest = sha2::Sha256::digest([seed.as_slice(), device_id.as_bytes(), &[ctr]].concat());
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&digest);
        let fb = p256::FieldBytes::from(candidate);
        if let Ok(sk) = P256SigningKey::from_bytes(&fb) {
            return Ok(sk);
        }
    }
    anyhow::bail!("failed to derive p256 key");
}

fn p256_public_jwk(vk: &P256VerifyingKey) -> anyhow::Result<serde_json::Value> {
    let point = vk.to_encoded_point(false);
    let x = point.x().context("p256 missing x")?;
    let y = point.y().context("p256 missing y")?;
    Ok(serde_json::json!({
      "kty": "EC",
      "crv": "P-256",
      "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
      "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y),
    }))
}

#[cfg(feature = "pkcs11")]
fn pkcs11_key_label_for_device(device_id: Uuid) -> String {
    format!("briefcase-remote-{device_id}")
}

#[cfg(feature = "pkcs11")]
mod pkcs11 {
    use super::*;

    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::error::{Error as Pkcs11Error, RvError};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
    use cryptoki::session::UserType;
    use cryptoki::types::AuthPin;
    use sha2::Digest as _;

    async fn spawn_blocking<T: Send + 'static>(
        f: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<T> {
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|e| anyhow::anyhow!("pkcs11 join error: {e}"))?
    }

    pub async fn ensure_and_load_public_key_bytes(
        module_path: &str,
        token_label: &str,
        user_pin: &str,
        key_label: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let module_path = module_path.to_string();
        let token_label = token_label.to_string();
        let user_pin = user_pin.to_string();
        let key_label = key_label.to_string();
        spawn_blocking(move || {
            ensure_keypair_blocking(&module_path, &token_label, &user_pin, &key_label)?;
            load_public_key_bytes_blocking(&module_path, &token_label, &user_pin, &key_label)
        })
        .await
    }

    pub async fn ensure_and_sign_p256(
        module_path: &str,
        token_label: &str,
        user_pin: &str,
        key_label: &str,
        msg: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let module_path = module_path.to_string();
        let token_label = token_label.to_string();
        let user_pin = user_pin.to_string();
        let key_label = key_label.to_string();
        let msg = msg.to_vec();
        spawn_blocking(move || {
            ensure_keypair_blocking(&module_path, &token_label, &user_pin, &key_label)?;
            sign_p256_blocking(&module_path, &token_label, &user_pin, &key_label, &msg)
        })
        .await
    }

    fn ensure_keypair_blocking(
        module_path: &str,
        token_label: &str,
        user_pin: &str,
        key_label: &str,
    ) -> anyhow::Result<()> {
        let (pkcs11, session) = open_user_session(module_path, token_label, user_pin)?;
        let label_bytes = key_label.as_bytes().to_vec();

        let res = (|| -> anyhow::Result<()> {
            let existing = session
                .find_objects(&[
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::Label(label_bytes.clone()),
                ])
                .unwrap_or_default();
            if !existing.is_empty() {
                return Ok(());
            }

            // secp256r1 OID.
            let secp256r1_oid: Vec<u8> =
                vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

            let pub_key_template = vec![
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::KeyType(KeyType::EC),
                Attribute::Verify(true),
                Attribute::EcParams(secp256r1_oid),
                Attribute::Label(label_bytes.clone()),
                Attribute::Id(label_bytes.clone()),
            ];

            let priv_key_template = vec![
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
                Attribute::Label(label_bytes.clone()),
                Attribute::Id(label_bytes.clone()),
            ];

            let _ = session
                .generate_key_pair(
                    &Mechanism::EccKeyPairGen,
                    &pub_key_template,
                    &priv_key_template,
                )
                .context("generate p256 keypair")?;

            Ok(())
        })();

        let _ = session.close();
        let _ = pkcs11.finalize();
        res
    }

    fn load_public_key_bytes_blocking(
        module_path: &str,
        token_label: &str,
        user_pin: &str,
        key_label: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let (pkcs11, session) = open_user_session(module_path, token_label, user_pin)?;

        let res = (|| -> anyhow::Result<Vec<u8>> {
            let label_bytes = key_label.as_bytes().to_vec();
            let mut objs = session
                .find_objects(&[
                    Attribute::Class(ObjectClass::PUBLIC_KEY),
                    Attribute::Label(label_bytes),
                ])
                .context("find public key")?;
            let obj = objs
                .pop()
                .ok_or_else(|| anyhow::anyhow!("pkcs11 public key not found"))?;

            let ec_point_attr = session
                .get_attributes(obj, &[AttributeType::EcPoint])
                .context("get EC_POINT")?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("missing EC_POINT attribute"))?;

            let raw = match ec_point_attr {
                Attribute::EcPoint(v) => v,
                _ => anyhow::bail!("unexpected EC_POINT attribute type"),
            };
            decode_ec_point(&raw)
        })();

        let _ = session.close();
        let _ = pkcs11.finalize();
        res
    }

    fn sign_p256_blocking(
        module_path: &str,
        token_label: &str,
        user_pin: &str,
        key_label: &str,
        msg: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let (pkcs11, session) = open_user_session(module_path, token_label, user_pin)?;

        let res = (|| -> anyhow::Result<Vec<u8>> {
            let label_bytes = key_label.as_bytes().to_vec();
            let mut objs = session
                .find_objects(&[
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::Label(label_bytes),
                ])
                .context("find private key")?;
            let obj = objs
                .pop()
                .ok_or_else(|| anyhow::anyhow!("pkcs11 private key not found"))?;

            // PKCS#11 CKM_ECDSA expects pre-hashed bytes.
            let digest = sha2::Sha256::digest(msg);
            let sig = session
                .sign(&Mechanism::Ecdsa, obj, &digest)
                .context("pkcs11 sign")?;
            Ok(sig)
        })();

        let _ = session.close();
        let _ = pkcs11.finalize();
        res
    }

    fn open_user_session(
        module_path: &str,
        token_label: &str,
        user_pin: &str,
    ) -> anyhow::Result<(Pkcs11, cryptoki::session::Session)> {
        let pkcs11 = Pkcs11::new(module_path).with_context(|| format!("load {module_path}"))?;
        match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) => {}
            Err(Pkcs11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(anyhow::Error::new(e)).context("pkcs11 initialize"),
        }

        let slot = find_slot_by_label(&pkcs11, token_label).context("find token slot")?;
        let session = pkcs11.open_rw_session(slot).context("open rw session")?;

        let pin = AuthPin::new(user_pin.to_string().into());
        session
            .login(UserType::User, Some(&pin))
            .context("pkcs11 login")?;

        Ok((pkcs11, session))
    }

    fn find_slot_by_label(
        pkcs11: &Pkcs11,
        token_label: &str,
    ) -> anyhow::Result<cryptoki::slot::Slot> {
        for slot in pkcs11.get_slots_with_token().context("list slots")? {
            if let Ok(info) = pkcs11.get_token_info(slot)
                && info.label() == token_label
            {
                return Ok(slot);
            }
        }
        anyhow::bail!("no PKCS#11 slot with token label {token_label:?}")
    }

    fn decode_ec_point(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        // SoftHSM typically returns CKA_EC_POINT as DER OCTET STRING wrapping the uncompressed point.
        if bytes.len() == 65 && bytes.first() == Some(&0x04) {
            return Ok(bytes.to_vec());
        }
        if bytes.len() >= 3 && bytes[0] == 0x04 {
            // DER length can be short-form or 0x81 long-form for small-ish values.
            let (len, off) = if bytes[1] & 0x80 == 0 {
                (bytes[1] as usize, 2usize)
            } else if bytes[1] == 0x81 && bytes.len() >= 3 {
                (bytes[2] as usize, 3usize)
            } else {
                anyhow::bail!("unsupported DER length form");
            };
            let end = off + len;
            if end <= bytes.len() {
                let inner = &bytes[off..end];
                if inner.len() == 65 && inner.first() == Some(&0x04) {
                    return Ok(inner.to_vec());
                }
            }
        }
        anyhow::bail!("unsupported EC_POINT encoding");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hyper=warn,sqlx=warn".into()),
        )
        .json()
        .init();

    let args = Args::parse();
    let policy_signer = parse_ed25519_seed(&args.policy_signing_key_seed_b64)?;
    let policy_pubkey_b64 = {
        let vk: VerifyingKey = policy_signer.verifying_key();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.to_bytes())
    };

    let remote_signer = build_remote_signer_backend(&args).context("init remote signer backend")?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&args.database_url)
        .await
        .context("connect to postgres")?;

    init_db(&pool).await?;
    seed_default_policy_bundle(&pool).await?;

    let public_base_url = match args.public_base_url.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Url::parse(raw).context("parse public_base_url")?,
        _ => Url::parse(&format!("http://{}", args.bind_addr))
            .context("build public_base_url from bind_addr")?,
    };

    let st = AppState {
        pool,
        admin_token: args.admin_token,
        auditor_token: args.auditor_token,
        policy_signer,
        policy_pubkey_b64,
        remote_signer,
        public_base_url,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/v1/admin/policy",
            get(admin_policy_get).post(admin_policy_set),
        )
        .route("/v1/admin/devices/enroll", post(admin_devices_enroll))
        .route("/v1/devices/{id}/policy", get(device_policy_get))
        .route("/v1/devices/{id}/receipts", post(device_receipts_upload))
        .route(
            "/v1/devices/{id}/remote-signer",
            get(device_remote_signer_get),
        )
        .route(
            "/v1/devices/{id}/remote-signer/sign",
            post(device_remote_signer_sign),
        )
        .route("/v1/audit/receipts", get(audit_list_receipts))
        .layer(TraceLayer::new_for_http())
        .with_state(st);

    info!(addr = %args.bind_addr, "briefcase-control-plane listening");
    let listener = tokio::net::TcpListener::bind(args.bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        ts: Utc::now().to_rfc3339(),
    })
}

async fn admin_policy_get(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<AdminSetPolicyResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_admin(&st, &headers)?;
    let bundle = latest_policy_bundle(&st.pool)
        .await
        .map_err(internal_error)?;
    let signed = sign_policy_bundle(&st, &bundle).map_err(internal_error)?;
    Ok(Json(AdminSetPolicyResponse {
        policy_bundle: signed,
    }))
}

async fn admin_policy_set(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AdminSetPolicyRequest>,
) -> Result<Json<AdminSetPolicyResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_admin(&st, &headers)?;

    let policy_text = req.policy_text.trim().to_string();
    if policy_text.is_empty() || policy_text.len() > MAX_POLICY_TEXT_BYTES {
        return Err(bad_request("invalid_policy_text"));
    }

    for (k, v) in &req.budgets {
        if k.trim().is_empty() || k.len() > 64 || *v < 0 {
            return Err(bad_request("invalid_budget"));
        }
    }

    let bundle = insert_policy_bundle(&st.pool, &policy_text, &req.budgets)
        .await
        .map_err(internal_error)?;
    let signed = sign_policy_bundle(&st, &bundle).map_err(internal_error)?;

    Ok(Json(AdminSetPolicyResponse {
        policy_bundle: signed,
    }))
}

async fn admin_devices_enroll(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<EnrollDeviceRequest>,
) -> Result<Json<EnrollDeviceResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_admin(&st, &headers)?;

    if req.device_name.trim().is_empty() || req.device_name.len() > 128 {
        return Err(bad_request("invalid_device_name"));
    }
    if req.device_pubkey_b64.trim().is_empty() || req.device_pubkey_b64.len() > 512 {
        return Err(bad_request("invalid_device_pubkey"));
    }

    // Device public key is used for DPoP binding; validate it's a real Ed25519 public key.
    let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(req.device_pubkey_b64.as_bytes())
        .map_err(|_| bad_request("invalid_device_pubkey"))?;
    if pk.len() != 32 {
        return Err(bad_request("invalid_device_pubkey"));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk);
    let _vk =
        VerifyingKey::from_bytes(&pk_arr).map_err(|_| bad_request("invalid_device_pubkey"))?;

    let device_token = random_token_b64url(32);
    let token_hash_hex = sha256_hex(device_token.as_bytes());

    upsert_device(
        &st.pool,
        req.device_id,
        &req.device_name,
        &req.device_pubkey_b64,
        &token_hash_hex,
    )
    .await
    .map_err(internal_error)?;

    let bundle = latest_policy_bundle(&st.pool)
        .await
        .map_err(internal_error)?;
    let signed = sign_policy_bundle(&st, &bundle).map_err(internal_error)?;

    let remote_signer = st
        .remote_signer
        .key_info(req.device_id)
        .await
        .map_err(internal_error)?;

    Ok(Json(EnrollDeviceResponse {
        device_id: req.device_id,
        device_token,
        policy_signing_pubkey_b64: st.policy_pubkey_b64.clone(),
        policy_bundle: signed,
        remote_signer: Some(remote_signer),
    }))
}

async fn device_policy_get(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<Uuid>,
    method: axum::http::Method,
    uri: axum::http::Uri,
) -> Result<Json<DevicePolicyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = require_device_bearer(&st, &headers, device_id).await?;
    require_device_sync_dpop(&st, &headers, device_id, &ctx, &method, &uri).await?;
    let bundle = latest_policy_bundle(&st.pool)
        .await
        .map_err(internal_error)?;
    let signed = sign_policy_bundle(&st, &bundle).map_err(internal_error)?;
    Ok(Json(DevicePolicyResponse {
        policy_bundle: signed,
    }))
}

async fn device_receipts_upload(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<Uuid>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    Json(req): Json<UploadReceiptsRequest>,
) -> Result<Json<UploadReceiptsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let ctx = require_device_bearer(&st, &headers, device_id).await?;
    require_device_sync_dpop(&st, &headers, device_id, &ctx, &method, &uri).await?;

    if req.receipts.len() > MAX_RECEIPTS_PER_UPLOAD {
        return Err(bad_request("too_many_receipts"));
    }

    // Sort ascending so we can verify chain and monotonicity.
    let mut receipts = req.receipts;
    receipts.sort_by_key(|r| r.id);

    let mut stored = 0usize;
    let mut tx = st.pool.begin().await.map_err(internal_error)?;

    let last: Option<(i64, String)> = sqlx::query(
        "SELECT receipt_id, hash_hex FROM receipts WHERE device_id=$1 ORDER BY receipt_id DESC LIMIT 1",
    )
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal_error)?
    .map(|row| (row.get::<i64, _>(0), row.get::<String, _>(1)));

    let mut expected_prev_hash = last
        .as_ref()
        .map(|(_, h)| h.clone())
        .unwrap_or_else(|| "0".repeat(64));
    let mut min_next_id = last.as_ref().map(|(id, _)| id + 1).unwrap_or(1);

    for r in receipts {
        if r.id < min_next_id {
            return Err(bad_request("receipt_id_not_monotonic"));
        }
        if r.prev_hash_hex != expected_prev_hash {
            return Err(bad_request("receipt_prev_hash_mismatch"));
        }

        let event_json =
            serde_json::to_string(&r.event).map_err(|e| internal_error(e.to_string()))?;
        let computed = sha256_hex_concat(&r.prev_hash_hex, event_json.as_bytes());
        if computed != r.hash_hex {
            return Err(bad_request("receipt_hash_mismatch"));
        }

        sqlx::query(
            "INSERT INTO receipts(device_id, receipt_id, ts, prev_hash_hex, hash_hex, event_json) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (device_id, receipt_id) DO NOTHING",
        )
        .bind(device_id)
        .bind(r.id)
        .bind(r.ts)
        .bind(&r.prev_hash_hex)
        .bind(&r.hash_hex)
        .bind(sqlx::types::Json(r.event))
        .execute(&mut *tx)
        .await
        .map_err(internal_error)?;

        stored += 1;
        expected_prev_hash = r.hash_hex;
        min_next_id = r.id + 1;
    }

    tx.commit().await.map_err(internal_error)?;

    Ok(Json(UploadReceiptsResponse { stored }))
}

async fn device_remote_signer_get(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Result<Json<DeviceRemoteSignerResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_device(&st, &headers, device_id).await?;
    let signer = st
        .remote_signer
        .key_info(device_id)
        .await
        .map_err(internal_error)?;
    Ok(Json(DeviceRemoteSignerResponse { signer }))
}

async fn device_remote_signer_sign(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<Uuid>,
    Json(req): Json<RemoteSignRequest>,
) -> Result<Json<RemoteSignResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_device(&st, &headers, device_id).await?;

    let expected_key_id = st.remote_signer.key_id_for_device(device_id);
    if req.key_id != expected_key_id {
        return Err(bad_request("invalid_key_id"));
    }

    let msg = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(req.msg_b64.as_bytes())
        .map_err(|_| bad_request("invalid_msg_b64"))?;
    if msg.is_empty() || msg.len() > MAX_REMOTE_SIGN_MSG_BYTES {
        return Err(bad_request("invalid_msg_size"));
    }

    let sig = st
        .remote_signer
        .sign(device_id, &msg)
        .await
        .map_err(internal_error)?;
    let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
    Ok(Json(RemoteSignResponse { signature_b64 }))
}

#[derive(Debug, serde::Deserialize)]
struct AuditQuery {
    device_id: Option<Uuid>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn audit_list_receipts(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Result<Json<AuditListReceiptsResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_auditor(&st, &headers)?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let offset = q.offset.unwrap_or(0).max(0);

    let rows = if let Some(device_id) = q.device_id {
        sqlx::query(
            "SELECT receipt_id, ts, prev_hash_hex, hash_hex, event_json
             FROM receipts WHERE device_id=$1
             ORDER BY receipt_id DESC LIMIT $2 OFFSET $3",
        )
        .bind(device_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&st.pool)
        .await
        .map_err(internal_error)?
    } else {
        sqlx::query(
            "SELECT receipt_id, ts, prev_hash_hex, hash_hex, event_json
             FROM receipts
             ORDER BY ts DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&st.pool)
        .await
        .map_err(internal_error)?
    };

    let mut receipts = Vec::new();
    for row in rows {
        let id: i64 = row.get(0);
        let ts: DateTime<Utc> = row.get(1);
        let prev_hash_hex: String = row.get(2);
        let hash_hex: String = row.get(3);
        let event: serde_json::Value = row.get::<sqlx::types::Json<serde_json::Value>, _>(4).0;
        receipts.push(briefcase_core::ReceiptRecord {
            id,
            ts,
            prev_hash_hex,
            hash_hex,
            event,
        });
    }

    Ok(Json(AuditListReceiptsResponse { receipts }))
}

fn random_token_b64url(nbytes: usize) -> String {
    let mut bytes = vec![0u8; nbytes];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn parse_ed25519_seed(seed_b64: &str) -> anyhow::Result<SigningKey> {
    let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seed_b64.as_bytes())
        .context("decode seed as base64url")?;
    if seed.len() != 32 {
        anyhow::bail!("policy signing seed must be 32 bytes");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed);
    Ok(SigningKey::from_bytes(&arr))
}

fn sign_policy_bundle(st: &AppState, bundle: &PolicyBundle) -> anyhow::Result<SignedPolicyBundle> {
    let bytes = serde_json::to_vec(bundle).context("serialize bundle")?;
    let sig: Signature = st.policy_signer.sign(&bytes);
    let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
    Ok(SignedPolicyBundle {
        bundle: bundle.clone(),
        signature_b64,
    })
}

fn require_admin(
    st: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let Some(tok) = bearer_token(headers) else {
        return Err(unauthorized("missing_token"));
    };
    if tok.as_bytes().ct_eq(st.admin_token.as_bytes()).unwrap_u8() != 1 {
        return Err(unauthorized("invalid_token"));
    }
    Ok(())
}

fn require_auditor(
    st: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let Some(tok) = bearer_token(headers) else {
        return Err(unauthorized("missing_token"));
    };
    let ok_admin = tok.as_bytes().ct_eq(st.admin_token.as_bytes()).unwrap_u8() == 1;
    let ok_auditor = tok
        .as_bytes()
        .ct_eq(st.auditor_token.as_bytes())
        .unwrap_u8()
        == 1;
    if !ok_admin && !ok_auditor {
        return Err(unauthorized("invalid_token"));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct DeviceAuthContext {
    token: String,
    device_pubkey_b64: String,
}

async fn require_device_bearer(
    st: &AppState,
    headers: &axum::http::HeaderMap,
    device_id: Uuid,
) -> Result<DeviceAuthContext, (StatusCode, Json<ErrorResponse>)> {
    let Some(tok) = bearer_token(headers) else {
        return Err(unauthorized("missing_token"));
    };
    let token_hash_hex = sha256_hex(tok.as_bytes());

    let row: Option<(String, String)> =
        sqlx::query_as("SELECT token_hash_hex, device_pubkey_b64 FROM devices WHERE id=$1")
            .bind(device_id)
            .fetch_optional(&st.pool)
            .await
            .map_err(internal_error)?;
    let Some((expected_hash, device_pubkey_b64)) = row else {
        return Err(unauthorized("unknown_device"));
    };
    if token_hash_hex
        .as_bytes()
        .ct_eq(expected_hash.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(unauthorized("invalid_token"));
    }

    // Best-effort last_seen update.
    let _ = sqlx::query("UPDATE devices SET last_seen=now() WHERE id=$1")
        .bind(device_id)
        .execute(&st.pool)
        .await;

    Ok(DeviceAuthContext {
        token: tok,
        device_pubkey_b64,
    })
}

async fn require_device(
    st: &AppState,
    headers: &axum::http::HeaderMap,
    device_id: Uuid,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let _ = require_device_bearer(st, headers, device_id).await?;
    Ok(())
}

async fn require_device_sync_dpop(
    st: &AppState,
    headers: &axum::http::HeaderMap,
    device_id: Uuid,
    ctx: &DeviceAuthContext,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    use std::collections::HashMap;

    let Some(jwt) = headers.get("dpop").and_then(|h| h.to_str().ok()) else {
        return Err(unauthorized("missing_dpop"));
    };

    let expected_jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": ctx.device_pubkey_b64.as_str(),
    });
    let expected_jkt = briefcase_dpop::jwk_thumbprint_b64url(&expected_jwk)
        .map_err(|_| unauthorized("invalid_dpop"))?;

    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());
    let expected_url = st
        .public_base_url
        .join(path_and_query)
        .map_err(internal_error)?;

    let mut used = HashMap::new();
    let claims = briefcase_dpop::verify_dpop_jwt(
        jwt,
        method.as_str(),
        &expected_url,
        Some(&ctx.token),
        Some(&expected_jkt),
        &mut used,
    )
    .map_err(|_| unauthorized("invalid_dpop"))?;

    let jti = claims.get("jti").and_then(|v| v.as_str()).unwrap_or("");
    let iat = claims.get("iat").and_then(|v| v.as_i64()).unwrap_or(0);
    if jti.is_empty() || iat <= 0 {
        return Err(unauthorized("invalid_dpop"));
    }

    // Best-effort cleanup to prevent unbounded growth.
    let _ = sqlx::query(
        "DELETE FROM device_dpop_jtis WHERE device_id=$1 AND inserted_at < now() - interval '10 minutes'",
    )
    .bind(device_id)
    .execute(&st.pool)
    .await;

    let res = sqlx::query(
        "INSERT INTO device_dpop_jtis(device_id, jti, iat) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(device_id)
    .bind(jti)
    .bind(iat)
    .execute(&st.pool)
    .await
    .map_err(internal_error)?;
    if res.rows_affected() == 0 {
        return Err(conflict("replay_detected"));
    }

    Ok(())
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let raw = raw.trim();
    let tok = raw.strip_prefix("Bearer ")?;
    if tok.is_empty() {
        return None;
    }
    Some(tok.to_string())
}

async fn init_db(pool: &PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await.context("begin tx")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS policy_bundles (
          bundle_id     BIGSERIAL PRIMARY KEY,
          compatibility_profile TEXT NOT NULL DEFAULT 'aacp_v1',
          policy_text   TEXT NOT NULL,
          budgets_json  JSONB NOT NULL,
          created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        "#,
    )
    .execute(&mut *tx)
    .await
    .context("create policy_bundles")?;

    // Best-effort migration for older DBs.
    sqlx::query(
        "ALTER TABLE policy_bundles ADD COLUMN IF NOT EXISTS compatibility_profile TEXT NOT NULL DEFAULT 'aacp_v1'",
    )
    .execute(&mut *tx)
    .await
    .context("alter policy_bundles compatibility_profile")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS devices (
          id                UUID PRIMARY KEY,
          device_name       TEXT NOT NULL,
          device_pubkey_b64 TEXT NOT NULL,
          token_hash_hex    TEXT NOT NULL,
          created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
          last_seen         TIMESTAMPTZ
        )
        "#,
    )
    .execute(&mut *tx)
    .await
    .context("create devices")?;

    // DPoP replay cache: store used `jti` values for device sync requests.
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS device_dpop_jtis (
          device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
          jti          TEXT NOT NULL,
          iat          BIGINT NOT NULL,
          inserted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
          PRIMARY KEY (device_id, jti)
        )
        "#,
    )
    .execute(&mut *tx)
    .await
    .context("create device_dpop_jtis")?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS device_dpop_jtis_inserted_idx ON device_dpop_jtis(inserted_at)",
    )
    .execute(&mut *tx)
    .await
    .context("create device_dpop_jtis_inserted_idx")?;
    sqlx::query("CREATE INDEX IF NOT EXISTS devices_token_hash_idx ON devices(token_hash_hex)")
        .execute(&mut *tx)
        .await
        .context("create devices_token_hash_idx")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS receipts (
          id            BIGSERIAL PRIMARY KEY,
          device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
          receipt_id    BIGINT NOT NULL,
          ts            TIMESTAMPTZ NOT NULL,
          prev_hash_hex TEXT NOT NULL,
          hash_hex      TEXT NOT NULL,
          event_json    JSONB NOT NULL,
          inserted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
          UNIQUE(device_id, receipt_id)
        )
        "#,
    )
    .execute(&mut *tx)
    .await
    .context("create receipts")?;
    sqlx::query("CREATE INDEX IF NOT EXISTS receipts_device_id_idx ON receipts(device_id)")
        .execute(&mut *tx)
        .await
        .context("create receipts_device_id_idx")?;
    sqlx::query("CREATE INDEX IF NOT EXISTS receipts_ts_idx ON receipts(ts)")
        .execute(&mut *tx)
        .await
        .context("create receipts_ts_idx")?;

    tx.commit().await.context("commit schema")?;
    Ok(())
}

async fn seed_default_policy_bundle(pool: &PgPool) -> anyhow::Result<()> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_bundles")
        .fetch_one(pool)
        .await
        .context("count policy_bundles")?;
    if n > 0 {
        return Ok(());
    }

    // Match the daemon defaults.
    let policy_text = briefcase_policy::CedarPolicyEngineOptions::default_policies().policy_text;
    let budgets: BTreeMap<String, i64> = BTreeMap::from([
        ("read".to_string(), 3_000_000),
        ("write".to_string(), 0),
        ("admin".to_string(), 0),
    ]);
    let _ = insert_policy_bundle(pool, &policy_text, &budgets).await?;
    Ok(())
}

async fn insert_policy_bundle(
    pool: &PgPool,
    policy_text: &str,
    budgets: &BTreeMap<String, i64>,
) -> anyhow::Result<PolicyBundle> {
    let row = sqlx::query(
        "INSERT INTO policy_bundles(compatibility_profile, policy_text, budgets_json) VALUES ($1, $2, $3) RETURNING bundle_id, created_at",
    )
    .bind(COMPATIBILITY_PROFILE_VERSION)
    .bind(policy_text)
    .bind(sqlx::types::Json(budgets))
    .fetch_one(pool)
    .await
    .context("insert policy bundle")?;

    let bundle_id: i64 = row.get(0);
    let created_at: DateTime<Utc> = row.get(1);
    Ok(PolicyBundle {
        bundle_id,
        compatibility_profile: COMPATIBILITY_PROFILE_VERSION.to_string(),
        policy_text: policy_text.to_string(),
        budgets: budgets.clone(),
        updated_at_rfc3339: created_at.to_rfc3339(),
    })
}

async fn latest_policy_bundle(pool: &PgPool) -> anyhow::Result<PolicyBundle> {
    let row = sqlx::query(
        "SELECT bundle_id, compatibility_profile, policy_text, budgets_json, created_at
         FROM policy_bundles ORDER BY bundle_id DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .context("fetch latest policy bundle")?;

    let bundle_id: i64 = row.get(0);
    let compatibility_profile: String = row.get(1);
    let policy_text: String = row.get(2);
    let budgets: BTreeMap<String, i64> =
        row.get::<sqlx::types::Json<BTreeMap<String, i64>>, _>(3).0;
    let created_at: DateTime<Utc> = row.get(4);
    Ok(PolicyBundle {
        bundle_id,
        compatibility_profile,
        policy_text,
        budgets,
        updated_at_rfc3339: created_at.to_rfc3339(),
    })
}

async fn upsert_device(
    pool: &PgPool,
    device_id: Uuid,
    device_name: &str,
    device_pubkey_b64: &str,
    token_hash_hex: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO devices(id, device_name, device_pubkey_b64, token_hash_hex)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT(id) DO UPDATE SET
          device_name=excluded.device_name,
          device_pubkey_b64=excluded.device_pubkey_b64,
          token_hash_hex=excluded.token_hash_hex
        "#,
    )
    .bind(device_id)
    .bind(device_name)
    .bind(device_pubkey_b64)
    .bind(token_hash_hex)
    .execute(pool)
    .await
    .context("upsert device")?;
    Ok(())
}

fn internal_error<E: std::fmt::Display>(e: E) -> (StatusCode, Json<ErrorResponse>) {
    error!(error = %e, "control plane request failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            code: "internal_error".to_string(),
            message: "internal error".to_string(),
        }),
    )
}

fn bad_request(code: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            code: code.to_string(),
            message: code.to_string(),
        }),
    )
}

fn unauthorized(code: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            code: code.to_string(),
            message: code.to_string(),
        }),
    )
}

fn conflict(code: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::CONFLICT,
        Json(ErrorResponse {
            code: code.to_string(),
            message: code.to_string(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p256_verify_key_from_jwk(jwk: &serde_json::Value) -> anyhow::Result<P256VerifyingKey> {
        let obj = jwk.as_object().context("jwk must be object")?;
        let kty = obj.get("kty").and_then(|v| v.as_str()).unwrap_or("");
        if kty != "EC" {
            anyhow::bail!("unsupported jwk.kty: {kty}");
        }
        let crv = obj.get("crv").and_then(|v| v.as_str()).unwrap_or("");
        if crv != "P-256" {
            anyhow::bail!("unsupported jwk.crv: {crv}");
        }
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
            anyhow::bail!("invalid p256 coordinate length");
        }
        let mut uncompressed = Vec::with_capacity(65);
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);
        let point = p256::EncodedPoint::from_bytes(&uncompressed).context("decode p256 point")?;
        P256VerifyingKey::from_encoded_point(&point).context("verifying key")
    }

    #[test]
    fn policy_signing_round_trips() -> anyhow::Result<()> {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let vk = signer.verifying_key();
        let bundle = PolicyBundle {
            bundle_id: 1,
            compatibility_profile: COMPATIBILITY_PROFILE_VERSION.to_string(),
            policy_text: "permit(principal, action, resource);".to_string(),
            budgets: BTreeMap::from([("read".to_string(), 1)]),
            updated_at_rfc3339: "2026-01-01T00:00:00Z".to_string(),
        };
        let bytes = serde_json::to_vec(&bundle)?;
        let sig: Signature = signer.sign(&bytes);
        vk.verify_strict(&bytes, &sig)?;
        Ok(())
    }

    #[test]
    fn receipt_hash_matches_core_impl() {
        let prev = "0".repeat(64);
        let event = serde_json::json!({"kind":"tool_call","tool_id":"echo"});
        let event_json = serde_json::to_string(&event).unwrap();
        let h = sha256_hex_concat(&prev, event_json.as_bytes());
        assert_eq!(h.len(), 64);
    }

    #[tokio::test]
    async fn derived_remote_signer_signs_and_verifies() -> anyhow::Result<()> {
        use p256::ecdsa::signature::Verifier as _;

        let backend = RemoteSignerBackend::DerivedP256 { seed: [1u8; 32] };
        let device_id = Uuid::new_v4();
        let info = backend.key_info(device_id).await?;
        assert_eq!(info.algorithm, "p256");

        let vk = p256_verify_key_from_jwk(&info.public_jwk)?;
        let sig_bytes = backend.sign(device_id, b"hello").await?;
        assert_eq!(sig_bytes.len(), 64);
        let sig = P256Signature::from_slice(&sig_bytes).context("parse signature")?;
        vk.verify(b"hello", &sig)?;
        Ok(())
    }

    #[cfg(feature = "pkcs11")]
    #[tokio::test]
    async fn pkcs11_remote_signer_signs_and_verifies() -> anyhow::Result<()> {
        use p256::ecdsa::signature::Verifier as _;

        let module_path = std::env::var("CONTROL_PLANE_PKCS11_MODULE")
            .ok()
            .or_else(|| std::env::var("BRIEFCASE_PKCS11_MODULE").ok());
        let token_label = std::env::var("CONTROL_PLANE_PKCS11_TOKEN_LABEL")
            .ok()
            .or_else(|| std::env::var("BRIEFCASE_PKCS11_TOKEN_LABEL").ok());
        let user_pin = std::env::var("CONTROL_PLANE_PKCS11_USER_PIN")
            .ok()
            .or_else(|| std::env::var("BRIEFCASE_PKCS11_USER_PIN").ok());

        let (Some(module_path), Some(token_label), Some(user_pin)) =
            (module_path, token_label, user_pin)
        else {
            // Running without SoftHSM/Vault harness.
            return Ok(());
        };

        let backend = RemoteSignerBackend::Pkcs11P256 {
            module_path,
            token_label,
            user_pin,
        };
        let device_id = Uuid::new_v4();
        let info = backend.key_info(device_id).await?;
        let vk = p256_verify_key_from_jwk(&info.public_jwk)?;
        let sig_bytes = backend.sign(device_id, b"hello").await?;
        assert_eq!(sig_bytes.len(), 64);
        let sig = P256Signature::from_slice(&sig_bytes).context("parse signature")?;
        vk.verify(b"hello", &sig)?;
        Ok(())
    }
}
