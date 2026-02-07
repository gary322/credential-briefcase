use std::io::{Read as _, Write as _};
use std::path::PathBuf;

use anyhow::Context as _;
use briefcase_payments::helper_protocol::{PaymentHelperRequest, PaymentHelperResponse};
use clap::Parser;
use secp256k1::SecretKey;

#[derive(Debug, Clone, clap::ValueEnum)]
#[clap(rename_all = "snake_case")]
enum L402Backend {
    Lnd,
    Cln,
}

#[derive(Debug, Parser)]
#[command(
    name = "briefcase-payment-helper",
    version,
    about = "External wallet/payment helper"
)]
struct Args {
    /// EVM private key as hex (32 bytes, with or without 0x prefix).
    ///
    /// WARNING: passing secrets via environment variables is convenient but not ideal for
    /// production deployments. Prefer a file-based secret reference and lock down permissions.
    #[arg(long, env = "BRIEFCASE_X402_EVM_PRIVATE_KEY_HEX")]
    evm_private_key_hex: Option<String>,

    /// Read EVM private key from a file (hex, with or without 0x prefix).
    #[arg(long, env = "BRIEFCASE_X402_EVM_PRIVATE_KEY_FILE")]
    evm_private_key_file: Option<PathBuf>,

    /// Which L402 Lightning backend to use for paying BOLT11 invoices.
    #[arg(long, env = "BRIEFCASE_L402_BACKEND")]
    l402_backend: Option<L402Backend>,

    /// LND gRPC endpoint for the payer node, e.g. `https://localhost:10009`.
    #[arg(long, env = "BRIEFCASE_LND_GRPC_ENDPOINT")]
    lnd_grpc_endpoint: Option<String>,

    /// LND TLS cert file (payer node).
    #[arg(long, env = "BRIEFCASE_LND_TLS_CERT_FILE")]
    lnd_tls_cert_file: Option<PathBuf>,

    /// LND admin macaroon file (payer node).
    #[arg(long, env = "BRIEFCASE_LND_MACAROON_FILE")]
    lnd_macaroon_file: Option<PathBuf>,

    /// Override the TLS SNI/hostname used for LND certificate verification.
    ///
    /// Useful when connecting to `https://127.0.0.1:...` but the cert is issued for `localhost`.
    #[arg(long, env = "BRIEFCASE_LND_TLS_DOMAIN")]
    lnd_tls_domain: Option<String>,

    /// Core Lightning JSON-RPC socket (payer node).
    #[arg(long, env = "BRIEFCASE_CLN_RPC_SOCKET")]
    cln_rpc_socket: Option<PathBuf>,

    /// Upper bound for CLN payment retries, in seconds.
    #[arg(long, env = "BRIEFCASE_L402_RETRY_FOR_SECONDS", default_value_t = 60)]
    l402_retry_for_seconds: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut input = Vec::new();
    std::io::stdin()
        .read_to_end(&mut input)
        .context("read stdin")?;
    if input.len() > 1024 * 1024 {
        anyhow::bail!("request too large");
    }

    let req: PaymentHelperRequest =
        serde_json::from_slice(&input).context("decode PaymentHelperRequest")?;

    let resp = handle_request(&args, req).await?;
    let out = serde_json::to_vec(&resp).context("encode PaymentHelperResponse")?;
    std::io::stdout().write_all(&out).context("write stdout")?;
    Ok(())
}

async fn handle_request(
    args: &Args,
    req: PaymentHelperRequest,
) -> anyhow::Result<PaymentHelperResponse> {
    match req {
        PaymentHelperRequest::X402V2 {
            payment_required, ..
        } => {
            let sk = load_evm_secret_key(args)?;
            let b64 = briefcase_payments::x402::evm::payment_signature_b64_for_eip3009(
                &sk,
                &payment_required,
            )?;
            Ok(PaymentHelperResponse::X402V2 {
                payment_signature_b64: b64,
            })
        }
        PaymentHelperRequest::X402 { .. } => {
            anyhow::bail!("legacy x402 is not supported by this helper (use daemon demo backend)")
        }
        PaymentHelperRequest::L402 {
            invoice: _invoice, ..
        } => {
            let backend = args
                .l402_backend
                .clone()
                .context("missing BRIEFCASE_L402_BACKEND (expected lnd or cln)")?;

            match backend {
                L402Backend::Lnd => {
                    #[cfg(feature = "l402-lnd")]
                    {
                        let endpoint = args
                            .lnd_grpc_endpoint
                            .clone()
                            .context("missing BRIEFCASE_LND_GRPC_ENDPOINT")?;
                        let tls = args
                            .lnd_tls_cert_file
                            .as_ref()
                            .context("missing BRIEFCASE_LND_TLS_CERT_FILE")?;
                        let mac = args
                            .lnd_macaroon_file
                            .as_ref()
                            .context("missing BRIEFCASE_LND_MACAROON_FILE")?;

                        let mut cfg = briefcase_payments::l402_lnd::LndGrpcConfig::from_files(
                            endpoint, tls, mac,
                        )?;
                        if let Some(domain) = args.lnd_tls_domain.as_deref() {
                            cfg = cfg.tls_domain_override(domain);
                        }

                        let mut client =
                            briefcase_payments::l402_lnd::LndGrpcClient::connect(cfg).await?;
                        let preimage = client.pay_invoice_preimage(&_invoice).await?;
                        let preimage_hex =
                            briefcase_payments::l402::preimage_hex_from_bytes(&preimage)?;
                        Ok(PaymentHelperResponse::L402 {
                            preimage: preimage_hex,
                        })
                    }
                    #[cfg(not(feature = "l402-lnd"))]
                    {
                        anyhow::bail!("helper is not built with feature l402-lnd");
                    }
                }
                L402Backend::Cln => {
                    #[cfg(all(feature = "l402-cln", unix))]
                    {
                        let socket = args
                            .cln_rpc_socket
                            .as_ref()
                            .context("missing BRIEFCASE_CLN_RPC_SOCKET")?;
                        let preimage_hex = briefcase_payments::l402_cln::pay_invoice_preimage_hex(
                            socket,
                            &_invoice,
                            args.l402_retry_for_seconds,
                        )
                        .await?;
                        Ok(PaymentHelperResponse::L402 {
                            preimage: preimage_hex,
                        })
                    }
                    #[cfg(any(not(feature = "l402-cln"), not(unix)))]
                    {
                        anyhow::bail!("helper is not built with feature l402-cln (unix only)");
                    }
                }
            }
        }
    }
}

fn load_evm_secret_key(args: &Args) -> anyhow::Result<SecretKey> {
    let raw = if let Some(v) = args.evm_private_key_hex.as_deref() {
        v.to_string()
    } else if let Some(p) = &args.evm_private_key_file {
        std::fs::read_to_string(p).with_context(|| format!("read key file {}", p.display()))?
    } else {
        anyhow::bail!(
            "missing EVM key: set BRIEFCASE_X402_EVM_PRIVATE_KEY_HEX or BRIEFCASE_X402_EVM_PRIVATE_KEY_FILE"
        )
    };

    let s = raw.trim().strip_prefix("0x").unwrap_or(raw.trim());
    let bytes = hex::decode(s).context("hex decode evm private key")?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32-byte EVM private key");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    SecretKey::from_byte_array(arr).context("parse secp256k1 secret key")
}
