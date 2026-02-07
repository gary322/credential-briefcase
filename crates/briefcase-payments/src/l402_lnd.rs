//! L402 via LND gRPC.
//!
//! This module is feature-gated (`l402-lnd`) because it pulls in `tonic` and
//! generated gRPC bindings.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::Context as _;
use base64::Engine as _;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error};
use tonic::codegen::InterceptedService;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};
use tower::Service;
use url::Url;

pub mod lnrpc {
    tonic::include_proto!("lnrpc");
}

#[derive(Clone)]
struct MacaroonInterceptor {
    macaroon_hex: MetadataValue<tonic::metadata::Ascii>,
}

impl Interceptor for MacaroonInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        req.metadata_mut()
            .insert("macaroon", self.macaroon_hex.clone());
        Ok(req)
    }
}

#[derive(Debug, Clone)]
pub struct LndGrpcConfig {
    /// gRPC endpoint URL, e.g. `https://localhost:10009`.
    pub endpoint: String,
    /// PEM-encoded TLS certificate for the server (self-signed in most setups).
    pub tls_cert_pem: Vec<u8>,
    /// Admin macaroon hex for authenticating requests.
    pub macaroon_hex: String,
    /// TLS "domain name" used for certificate verification (SNI + hostname check).
    pub tls_domain: String,
}

impl LndGrpcConfig {
    pub fn from_files(
        endpoint: impl Into<String>,
        tls_cert_file: &Path,
        macaroon_file: &Path,
    ) -> anyhow::Result<Self> {
        let endpoint: String = endpoint.into();
        let url = Url::parse(&endpoint).context("parse lnd endpoint url")?;
        if url.scheme() != "https" {
            anyhow::bail!("lnd endpoint must be https");
        }

        let tls_domain = url
            .host_str()
            .context("lnd endpoint missing host")?
            .to_string();

        let tls_cert_pem = std::fs::read(tls_cert_file)
            .with_context(|| format!("read lnd tls cert {}", tls_cert_file.display()))?;

        let macaroon = std::fs::read(macaroon_file)
            .with_context(|| format!("read lnd macaroon {}", macaroon_file.display()))?;
        let macaroon_hex = hex::encode(macaroon);

        Ok(Self {
            endpoint,
            tls_cert_pem,
            macaroon_hex,
            tls_domain,
        })
    }

    pub fn tls_domain_override(mut self, tls_domain: impl Into<String>) -> Self {
        self.tls_domain = tls_domain.into();
        self
    }
}

#[derive(Clone)]
struct LndPinnedConnector {
    tls: TlsConnector,
    server_name: ServerName<'static>,
}

impl Service<http::Uri> for LndPinnedConnector {
    type Response = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let tls = self.tls.clone();
        let server_name = self.server_name.clone();

        Box::pin(async move {
            let host = uri.host().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing uri host")
            })?;
            let port = uri.port_u16().unwrap_or(443);

            let tcp = TcpStream::connect((host, port)).await?;
            let tls_stream = tls.connect(server_name, tcp).await?;
            Ok(TokioIo::new(tls_stream))
        })
    }
}

#[derive(Debug)]
struct LndPinnedCertVerifier {
    pinned_end_entity_der: Vec<u8>,
    inner: std::sync::Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for LndPinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if end_entity.as_ref() != self.pinned_end_entity_der.as_slice() {
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn first_pem_cert_to_der(pem: &[u8]) -> anyhow::Result<Vec<u8>> {
    let s = std::str::from_utf8(pem).context("tls cert is not utf-8")?;

    let mut in_block = false;
    let mut b64 = String::new();
    for line in s.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            break;
        }
        if in_block && !line.is_empty() {
            b64.push_str(line);
        }
    }

    if b64.is_empty() {
        anyhow::bail!("no PEM CERTIFICATE block found");
    }

    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .context("base64 decode tls cert")?;
    Ok(der)
}

#[derive(Clone)]
pub struct LndGrpcClient {
    inner:
        lnrpc::lightning_client::LightningClient<InterceptedService<Channel, MacaroonInterceptor>>,
}

impl LndGrpcClient {
    pub async fn connect(cfg: LndGrpcConfig) -> anyhow::Result<Self> {
        // LND's autogenerated `tls.cert` is a self-signed CA cert. Rustls rejects it as an
        // end-entity cert (`CaUsedAsEndEntity`). We pin the exact server certificate bytes
        // instead of doing PKI chain validation.
        //
        // This keeps the default local dev / regtest setup secure against MITM without requiring
        // users to provision "proper" TLS.
        let pinned_der = first_pem_cert_to_der(&cfg.tls_cert_pem)?;
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add_parsable_certificates([CertificateDer::from(pinned_der.clone())]);
        let roots = std::sync::Arc::new(roots);

        // Explicitly choose the crypto provider to avoid rustls panics when multiple providers
        // are enabled via transitive crate features.
        let provider = std::sync::Arc::new(crypto::ring::default_provider());

        let webpki = WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
            .build()
            .context("build webpki verifier")?;
        let verifier = std::sync::Arc::new(LndPinnedCertVerifier {
            pinned_end_entity_der: pinned_der,
            inner: webpki,
        });

        let mut tls_cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        tls_cfg.alpn_protocols.push(b"h2".to_vec());

        let server_name: ServerName<'static> = ServerName::try_from(cfg.tls_domain.as_str())
            .context("parse lnd tls domain")?
            .to_owned();
        let connector = LndPinnedConnector {
            tls: TlsConnector::from(std::sync::Arc::new(tls_cfg)),
            server_name,
        };

        // Tonic's connector wrapper treats `https://` URIs specially and will error if no
        // built-in TLS config is configured. Since we perform TLS in the custom connector, we
        // intentionally use an `http://` URI here.
        let url = Url::parse(&cfg.endpoint).context("parse lnd endpoint url")?;
        let host = url.host_str().context("lnd endpoint missing host")?;
        let port = url.port_or_known_default().unwrap_or(443);
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        let endpoint_uri = format!("http://{host}:{port}");
        let endpoint = Endpoint::from_shared(endpoint_uri).context("build lnd endpoint")?;
        let channel = endpoint
            .connect_with_connector(connector)
            .await
            .context("connect to lnd")?;

        let macaroon_hex = MetadataValue::try_from(cfg.macaroon_hex)
            .context("macaroon hex is not valid metadata")?;
        let interceptor = MacaroonInterceptor { macaroon_hex };
        let inner =
            lnrpc::lightning_client::LightningClient::with_interceptor(channel, interceptor);
        Ok(Self { inner })
    }

    pub async fn add_invoice(
        &mut self,
        memo: &str,
        value_sat: i64,
        expiry_seconds: i64,
    ) -> anyhow::Result<lnrpc::AddInvoiceResponse> {
        let invoice = lnrpc::Invoice {
            memo: memo.to_string(),
            value: value_sat,
            expiry: expiry_seconds,
            ..Default::default()
        };
        let resp = self
            .inner
            .add_invoice(invoice)
            .await
            .context("lnd AddInvoice")?
            .into_inner();
        Ok(resp)
    }

    pub async fn lookup_invoice(&mut self, r_hash: &[u8]) -> anyhow::Result<lnrpc::Invoice> {
        let req = lnrpc::PaymentHash {
            r_hash: r_hash.to_vec(),
        };
        let resp = self
            .inner
            .lookup_invoice(req)
            .await
            .context("lnd LookupInvoice")?
            .into_inner();
        Ok(resp)
    }

    pub async fn pay_invoice_preimage(&mut self, payment_request: &str) -> anyhow::Result<Vec<u8>> {
        let req = lnrpc::SendRequest {
            payment_request: payment_request.to_string(),
        };
        let resp = self
            .inner
            .send_payment_sync(req)
            .await
            .context("lnd SendPaymentSync")?
            .into_inner();

        if !resp.payment_error.is_empty() {
            anyhow::bail!("lnd payment error: {}", resp.payment_error);
        }
        Ok(resp.payment_preimage)
    }
}
