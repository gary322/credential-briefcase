//! L402 via Core Lightning JSON-RPC (Unix socket).
//!
//! This module is feature-gated (`l402-cln`) and only available on Unix.

use std::path::Path;

use anyhow::Context as _;
use cln_rpc::ClnRpc;
use cln_rpc::model::requests::{InvoiceRequest, ListinvoicesRequest, PayRequest};
use cln_rpc::model::responses::{
    InvoiceResponse, ListinvoicesInvoicesStatus, ListinvoicesResponse, PayResponse,
};
use cln_rpc::primitives::{Amount, AmountOrAny};

#[derive(Debug, Clone)]
pub struct ClnInvoice {
    pub bolt11: String,
    pub payment_hash_hex: String,
}

pub async fn create_invoice(
    socket_path: &Path,
    amount_msat: u64,
    label: &str,
    description: &str,
    expiry_seconds: Option<u64>,
) -> anyhow::Result<ClnInvoice> {
    let mut rpc = ClnRpc::new(socket_path)
        .await
        .with_context(|| format!("connect to cln rpc {}", socket_path.display()))?;

    let req = InvoiceRequest {
        cltv: None,
        deschashonly: None,
        expiry: expiry_seconds,
        preimage: None,
        exposeprivatechannels: None,
        fallbacks: None,
        amount_msat: AmountOrAny::Amount(Amount::from_msat(amount_msat)),
        description: description.to_string(),
        label: label.to_string(),
    };

    let resp: InvoiceResponse = rpc.call_typed(&req).await.context("cln invoice")?;
    Ok(ClnInvoice {
        bolt11: resp.bolt11,
        payment_hash_hex: resp.payment_hash.to_string(),
    })
}

pub async fn is_invoice_paid(socket_path: &Path, payment_hash_hex: &str) -> anyhow::Result<bool> {
    let mut rpc = ClnRpc::new(socket_path)
        .await
        .with_context(|| format!("connect to cln rpc {}", socket_path.display()))?;

    let req = ListinvoicesRequest {
        index: None,
        invstring: None,
        label: None,
        limit: Some(10),
        offer_id: None,
        payment_hash: Some(payment_hash_hex.to_string()),
        start: None,
    };

    let resp: ListinvoicesResponse = rpc.call_typed(&req).await.context("cln listinvoices")?;

    Ok(resp
        .invoices
        .iter()
        .any(|inv| inv.status == ListinvoicesInvoicesStatus::PAID))
}

pub async fn pay_invoice_preimage_hex(
    socket_path: &Path,
    bolt11: &str,
    retry_for_seconds: u16,
) -> anyhow::Result<String> {
    let mut rpc = ClnRpc::new(socket_path)
        .await
        .with_context(|| format!("connect to cln rpc {}", socket_path.display()))?;

    let req = PayRequest {
        amount_msat: None,
        description: None,
        exemptfee: None,
        label: None,
        localinvreqid: None,
        maxdelay: None,
        maxfee: None,
        maxfeepercent: None,
        partial_msat: None,
        retry_for: Some(retry_for_seconds),
        riskfactor: None,
        exclude: None,
        bolt11: bolt11.to_string(),
    };

    let resp: PayResponse = rpc.call_typed(&req).await.context("cln pay")?;
    if resp.status != cln_rpc::model::responses::PayStatus::COMPLETE {
        anyhow::bail!("cln pay status not complete: {:?}", resp.status);
    }

    Ok(hex::encode(resp.payment_preimage.to_vec()))
}
