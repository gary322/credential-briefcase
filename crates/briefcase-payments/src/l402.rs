//! L402 / LSAT helpers.
//!
//! For v1 we keep L402 encoding simple:
//! - Provider returns `{ invoice, macaroon }` in a 402 challenge.
//! - Client pays the BOLT11 invoice and obtains a 32-byte preimage.
//! - Client retries with `Authorization: L402 <macaroon>:<preimage_hex>`.
//!
//! The macaroon is treated as an opaque provider token (not a full macaroon implementation).

use anyhow::Context as _;
use lightning_invoice::Bolt11Invoice;
use sha2::{Digest as _, Sha256};
use std::str::FromStr;

pub fn preimage_bytes_from_hex(preimage_hex: &str) -> anyhow::Result<[u8; 32]> {
    let raw = hex::decode(preimage_hex.trim()).context("hex decode preimage")?;
    if raw.len() != 32 {
        anyhow::bail!("preimage must be 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub fn preimage_hex_from_bytes(preimage: &[u8]) -> anyhow::Result<String> {
    if preimage.len() != 32 {
        anyhow::bail!("preimage must be 32 bytes");
    }
    Ok(hex::encode(preimage))
}

pub fn payment_hash_hex_for_preimage(preimage: &[u8]) -> anyhow::Result<String> {
    if preimage.len() != 32 {
        anyhow::bail!("preimage must be 32 bytes");
    }
    let mut h = Sha256::new();
    h.update(preimage);
    Ok(hex::encode(h.finalize()))
}

pub fn payment_hash_hex_for_preimage_hex(preimage_hex: &str) -> anyhow::Result<String> {
    let preimage = preimage_bytes_from_hex(preimage_hex)?;
    payment_hash_hex_for_preimage(&preimage)
}

pub fn payment_hash_hex_from_bolt11(invoice: &str) -> anyhow::Result<String> {
    let inv = Bolt11Invoice::from_str(invoice)
        .map_err(|e| anyhow::anyhow!("parse bolt11 invoice: {e:?}"))?;
    Ok(inv.payment_hash().to_string())
}
