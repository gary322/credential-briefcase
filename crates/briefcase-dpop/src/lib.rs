use std::collections::HashMap;

use anyhow::Context as _;
use base64::Engine as _;
use briefcase_keys::{KeyAlgorithm, Signer};
use chrono::Utc;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier as _, VerifyingKey};
use sha2::Digest as _;
use url::Url;
use uuid::Uuid;

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn sha256_b64url(msg: &[u8]) -> String {
    let digest = sha2::Sha256::digest(msg);
    b64url(&digest)
}

fn jws_alg_for_key(alg: &KeyAlgorithm) -> &'static str {
    match alg {
        KeyAlgorithm::Ed25519 => "EdDSA",
        KeyAlgorithm::P256 => "ES256",
    }
}

/// RFC 7638 JWK thumbprint, base64url(sha256(canonical_jwk_json)).
///
/// This is used for DPoP token binding via the `cnf.jkt` claim.
pub fn jwk_thumbprint_b64url(jwk: &serde_json::Value) -> anyhow::Result<String> {
    let obj = jwk
        .as_object()
        .context("jwk must be a JSON object")?
        .clone();
    let kty = obj
        .get("kty")
        .and_then(|v| v.as_str())
        .context("jwk.kty missing")?;

    // Canonical serialization requires lexicographic key ordering and no extra whitespace.
    // We hardcode the minimal required members for the supported key types.
    let canonical = match kty {
        "OKP" => {
            let crv = obj
                .get("crv")
                .and_then(|v| v.as_str())
                .context("jwk.crv missing")?;
            if crv != "Ed25519" {
                anyhow::bail!("unsupported OKP crv: {crv}");
            }
            let x = obj
                .get("x")
                .and_then(|v| v.as_str())
                .context("jwk.x missing")?;
            format!("{{\"crv\":\"{crv}\",\"kty\":\"OKP\",\"x\":\"{x}\"}}")
        }
        "EC" => {
            let crv = obj
                .get("crv")
                .and_then(|v| v.as_str())
                .context("jwk.crv missing")?;
            if crv != "P-256" {
                anyhow::bail!("unsupported EC crv: {crv}");
            }
            let x = obj
                .get("x")
                .and_then(|v| v.as_str())
                .context("jwk.x missing")?;
            let y = obj
                .get("y")
                .and_then(|v| v.as_str())
                .context("jwk.y missing")?;
            format!("{{\"crv\":\"{crv}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")
        }
        _ => anyhow::bail!("unsupported jwk.kty: {kty}"),
    };

    let digest = sha2::Sha256::digest(canonical.as_bytes());
    Ok(b64url(&digest))
}

async fn dpop_proof_internal(
    signer: &dyn Signer,
    htu: &Url,
    htm: &str,
    access_token: Option<&str>,
) -> anyhow::Result<String> {
    let jwk = signer.public_jwk().await.context("get dpop jwk")?;
    let alg = jws_alg_for_key(&signer.handle().algorithm);

    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": alg,
        "jwk": jwk,
    });

    let mut u = htu.clone();
    u.set_fragment(None);

    let iat = Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();

    let mut claims = serde_json::Map::new();
    claims.insert("htu".to_string(), serde_json::Value::String(u.to_string()));
    claims.insert(
        "htm".to_string(),
        serde_json::Value::String(htm.to_uppercase()),
    );
    claims.insert("iat".to_string(), serde_json::Value::Number(iat.into()));
    claims.insert("jti".to_string(), serde_json::Value::String(jti));
    if let Some(at) = access_token {
        claims.insert(
            "ath".to_string(),
            serde_json::Value::String(sha256_b64url(at.as_bytes())),
        );
    }
    let payload = serde_json::Value::Object(claims);

    let header_b64 = b64url(&serde_json::to_vec(&header).context("serialize dpop header")?);
    let payload_b64 = b64url(&serde_json::to_vec(&payload).context("serialize dpop payload")?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = signer
        .sign(signing_input.as_bytes())
        .await
        .context("sign dpop jwt")?;
    let sig_b64 = b64url(&sig);
    Ok(format!("{signing_input}.{sig_b64}"))
}

pub async fn dpop_proof_for_token_endpoint(
    signer: &dyn Signer,
    token_endpoint: &Url,
) -> anyhow::Result<String> {
    dpop_proof_internal(signer, token_endpoint, "POST", None).await
}

pub async fn dpop_proof_for_resource_request(
    signer: &dyn Signer,
    resource_url: &Url,
    method: &str,
    access_token: &str,
) -> anyhow::Result<String> {
    dpop_proof_internal(signer, resource_url, method, Some(access_token)).await
}

fn decode_b64url(s: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .context("b64url decode")
}

/// Verify a DPoP proof JWT per RFC 9449 (subset).
///
/// - Supports `EdDSA` (Ed25519) and `ES256` (P-256).
/// - Enforces `htu`, `htm`, `iat`, `jti`.
/// - If `access_token` is provided, enforces `ath`.
/// - If `expected_jkt` is provided, enforces that the JWK thumbprint matches it.
/// - Provides best-effort replay defense using `used_jtis`.
pub fn verify_dpop_jwt(
    jwt: &str,
    method: &str,
    expected_url: &Url,
    access_token: Option<&str>,
    expected_jkt: Option<&str>,
    used_jtis: &mut HashMap<String, i64>,
) -> anyhow::Result<VerifiedDpopJwt> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("invalid jwt format");
    }
    let header_bytes = decode_b64url(parts[0]).context("decode header")?;
    let payload_bytes = decode_b64url(parts[1]).context("decode payload")?;
    let sig_bytes = decode_b64url(parts[2]).context("decode signature")?;

    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).context("parse header")?;
    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).context("parse payload")?;

    let typ = header
        .get("typ")
        .and_then(|v| v.as_str())
        .context("missing typ")?;
    if typ != "dpop+jwt" {
        anyhow::bail!("unexpected typ");
    }

    let jwk = header.get("jwk").cloned().context("missing jwk")?;
    let jkt = jwk_thumbprint_b64url(&jwk).context("compute jkt")?;

    if let Some(expected) = expected_jkt
        && expected != jkt
    {
        anyhow::bail!("jkt mismatch");
    }

    let htu = payload
        .get("htu")
        .and_then(|v| v.as_str())
        .context("missing htu")?;
    let htm = payload
        .get("htm")
        .and_then(|v| v.as_str())
        .context("missing htm")?;

    let mut u = expected_url.clone();
    u.set_fragment(None);
    if htu != u.to_string() || !htm.eq_ignore_ascii_case(method) {
        anyhow::bail!("htu/htm mismatch");
    }

    let iat = payload
        .get("iat")
        .and_then(|v| v.as_i64())
        .context("missing iat")?;
    let jti = payload
        .get("jti")
        .and_then(|v| v.as_str())
        .context("missing jti")?;
    if jti.is_empty() || jti.len() > 128 {
        anyhow::bail!("invalid jti");
    }

    let now = Utc::now().timestamp();
    const MAX_SKEW_SECS: i64 = 120;
    if (now - iat).abs() > MAX_SKEW_SECS {
        anyhow::bail!("iat outside skew");
    }

    // Optional access token hash binding.
    if let Some(at) = access_token {
        let ath = payload
            .get("ath")
            .and_then(|v| v.as_str())
            .context("missing ath")?;
        if ath != sha256_b64url(at.as_bytes()) {
            anyhow::bail!("ath mismatch");
        }
    }

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .context("missing alg")?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);

    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .context("missing jwk.kty")?;

    match (kty, alg) {
        ("OKP", "EdDSA") => {
            let crv = jwk
                .get("crv")
                .and_then(|v| v.as_str())
                .context("missing jwk.crv")?;
            if crv != "Ed25519" {
                anyhow::bail!("unsupported okp crv");
            }
            let x_b64 = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .context("missing jwk.x")?;
            let pk_bytes: [u8; 32] = decode_b64url(x_b64)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad okp key length"))?;
            let vk = VerifyingKey::from_bytes(&pk_bytes).context("decode ed25519 key")?;
            let sig_bytes: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad signature length"))?;
            let sig = Ed25519Signature::from_bytes(&sig_bytes);
            vk.verify(signing_input.as_bytes(), &sig)
                .context("verify ed25519")?;
        }
        ("EC", "ES256") => {
            use p256::ecdsa::signature::Verifier as _;
            use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};

            let crv = jwk
                .get("crv")
                .and_then(|v| v.as_str())
                .context("missing jwk.crv")?;
            if crv != "P-256" {
                anyhow::bail!("unsupported ec crv");
            }
            let x_b64 = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .context("missing jwk.x")?;
            let y_b64 = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .context("missing jwk.y")?;

            let x = decode_b64url(x_b64)?;
            let y = decode_b64url(y_b64)?;
            if x.len() != 32 || y.len() != 32 {
                anyhow::bail!("bad ec coordinate length");
            }

            let mut sec1 = [0u8; 65];
            sec1[0] = 0x04;
            sec1[1..33].copy_from_slice(&x);
            sec1[33..65].copy_from_slice(&y);
            let point = p256::EncodedPoint::from_bytes(sec1).context("decode point")?;
            let vk =
                P256VerifyingKey::from_encoded_point(&point).context("decode verifying key")?;

            let sig = P256Signature::from_slice(&sig_bytes).context("decode signature")?;
            vk.verify(signing_input.as_bytes(), &sig)
                .context("verify p256")?;
        }
        _ => anyhow::bail!("unsupported alg/kty pair"),
    }

    // Replay defense: `${jkt}:${jti}` must be unique. Do this *after* signature verification so
    // invalid proofs can't fill the cache.
    let replay_key = format!("{jkt}:{jti}");
    if used_jtis.contains_key(&replay_key) {
        anyhow::bail!("replayed jti");
    }
    used_jtis.insert(replay_key, iat);

    Ok(VerifiedDpopJwt { jwk, payload, jkt })
}

#[derive(Debug, Clone)]
pub struct VerifiedDpopJwt {
    /// Public key presented in the DPoP header.
    pub jwk: serde_json::Value,
    /// Verified JWT payload (contains `htu`, `htm`, `iat`, `jti`, and optional `ath`).
    pub payload: serde_json::Value,
    /// RFC 7638 thumbprint of `jwk` (base64url-encoded sha256 of the canonical JWK JSON).
    pub jkt: String,
}
