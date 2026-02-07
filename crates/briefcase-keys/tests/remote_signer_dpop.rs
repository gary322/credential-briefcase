use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use briefcase_core::Sensitive;
use briefcase_keys::KeyAlgorithm;
use briefcase_keys::remote::RemoteKeyManager;
use p256::ecdsa::{Signature as P256Sig, SigningKey as P256Sk};
use tokio::sync::Mutex;
use url::Url;

#[derive(Debug, Clone, serde::Deserialize)]
struct RemoteSignRequest {
    key_id: String,
    msg_b64: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RemoteSignResponse {
    signature_b64: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct DeviceRemoteSignerResponse {
    signer: RemoteSignerKeyInfo,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RemoteSignerKeyInfo {
    key_id: String,
    algorithm: String,
    public_jwk: serde_json::Value,
}

#[derive(Clone)]
struct MockState {
    token: String,
    device_id: String,
    key_id: String,
    sk: Arc<Mutex<P256Sk>>,
    sign_calls: Arc<Mutex<u64>>,
}

fn bearer_ok(headers: &HeaderMap, want: &str) -> bool {
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
    if !bearer_ok(&headers, &st.token) || device_id != st.device_id {
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
    use p256::ecdsa::signature::Signer as _;

    if !bearer_ok(&headers, &st.token) || device_id != st.device_id {
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

    *st.sign_calls.lock().await += 1;

    Ok(Json(RemoteSignResponse {
        signature_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    }))
}

#[tokio::test]
async fn remote_signer_can_generate_and_verify_dpop() -> anyhow::Result<()> {
    use briefcase_dpop::verify_dpop_jwt;
    use std::collections::HashMap;

    let token = "tok";
    let device_id = "00000000-0000-0000-0000-000000000001";
    let key_id = "k1";

    let sk = P256Sk::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let st = MockState {
        token: token.to_string(),
        device_id: device_id.to_string(),
        key_id: key_id.to_string(),
        sk: Arc::new(Mutex::new(sk)),
        sign_calls: Arc::new(Mutex::new(0)),
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
    let km = RemoteKeyManager::new(secrets)?;
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
    let url = Url::parse("https://example.com/token")?;
    let proof = briefcase_dpop::dpop_proof_for_token_endpoint(signer.as_ref(), &url).await?;
    let mut used = HashMap::new();
    let _claims = verify_dpop_jwt(&proof, "POST", &url, None, None, &mut used)?;

    assert!(
        *st.sign_calls.lock().await > 0,
        "expected remote signer sign endpoint to be called"
    );

    task.abort();
    Ok(())
}
