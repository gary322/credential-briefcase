#![cfg(all(feature = "tpm2", target_os = "linux"))]

use std::sync::Arc;

use anyhow::Context as _;
use briefcase_keys::KeyAlgorithm;
use briefcase_keys::tpm2::Tpm2KeyManager;
use p256::ecdsa::signature::Verifier as _;

#[tokio::test]
async fn tpm2_p256_sign_and_verify_with_swtpm() -> anyhow::Result<()> {
    let Ok(tcti) = std::env::var("BRIEFCASE_TPM2_TCTI") else {
        eprintln!("skipping: BRIEFCASE_TPM2_TCTI not set");
        return Ok(());
    };

    let secrets = Arc::new(briefcase_secrets::InMemorySecretStore::default());
    let km = Tpm2KeyManager::new(secrets);

    let handle = km.generate_p256(tcti).await?;
    assert_eq!(handle.algorithm, KeyAlgorithm::P256);

    let signer = km.signer(handle.clone());

    let msg = b"hello tpm2";
    let sig_bytes = signer.sign(msg).await?;
    assert_eq!(sig_bytes.len(), 64);

    let pk_bytes = signer.public_key_bytes().await?;
    let point = p256::EncodedPoint::from_bytes(&pk_bytes).context("decode p256 point")?;
    let verifying =
        p256::ecdsa::VerifyingKey::from_encoded_point(&point).context("verifying key")?;

    let sig = p256::ecdsa::Signature::from_slice(&sig_bytes).context("decode raw signature")?;
    verifying.verify(msg, &sig).context("verify signature")?;

    km.delete(&handle).await?;
    Ok(())
}
