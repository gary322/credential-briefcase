use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use briefcase_secrets::{SecretStoreKind, SecretStoreOptions};
use clap::Parser;
use directories::ProjectDirs;
use rand::RngCore;
use tracing::info;

use base64::Engine as _;

mod app;
mod db;
mod firewall;
mod middleware;
mod provider;
mod remote_mcp;
mod tools;

#[derive(Debug, Clone, Parser)]
#[command(name = "briefcased", version, about = "Credential Briefcase daemon")]
struct Args {
    /// Directory for runtime state (db, auth token, socket).
    #[arg(long, env = "BRIEFCASE_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Listen on a TCP address (e.g. 127.0.0.1:0). Not the default on Unix.
    #[arg(long, env = "BRIEFCASE_TCP_ADDR")]
    tcp_addr: Option<SocketAddr>,

    /// Listen on a Unix domain socket path. Default: <data_dir>/briefcased.sock (Unix only).
    #[arg(long, env = "BRIEFCASE_UNIX_SOCKET")]
    unix_socket: Option<PathBuf>,

    /// Base URL for the reference provider gateway.
    #[arg(
        long,
        env = "BRIEFCASE_PROVIDER_BASE_URL",
        default_value = "http://127.0.0.1:9099"
    )]
    provider_base_url: String,

    /// Secret storage backend: `keyring`, `file`, or `memory` (tests/dev only).
    ///
    /// If unset:
    /// - uses `file` when `BRIEFCASE_MASTER_PASSPHRASE` is set
    /// - otherwise uses `keyring`
    #[arg(long, env = "BRIEFCASE_SECRET_BACKEND")]
    secret_backend: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hyper=warn,reqwest=warn".into()),
        )
        .json()
        .init();

    let args = Args::parse();
    let data_dir = resolve_data_dir(args.data_dir.as_deref())?;
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("create data dir {}", data_dir.display()))?;

    let auth_token_path = data_dir.join("auth_token");
    let auth_token = load_or_create_auth_token(&auth_token_path)?;

    let db_path = data_dir.join("briefcase.sqlite");
    let secrets = open_secret_store(&data_dir, args.secret_backend.as_deref()).await?;
    let state = app::AppState::init(
        &db_path,
        auth_token.clone(),
        args.provider_base_url,
        secrets,
    )
    .await?;

    #[cfg(unix)]
    let should_use_unix = args.tcp_addr.is_none();
    #[cfg(not(unix))]
    let should_use_unix = false;

    if should_use_unix {
        #[cfg(unix)]
        {
            let sock_path = args
                .unix_socket
                .unwrap_or_else(|| data_dir.join("briefcased.sock"));
            info!(path = %sock_path.display(), "starting briefcased (unix socket)");
            app::serve_unix(sock_path, state).await?;
            return Ok(());
        }
        #[cfg(not(unix))]
        {
            tracing::warn!("unix sockets are not supported on this platform; falling back to TCP");
        }
    }

    let addr = args
        .tcp_addr
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
    info!(addr = %addr, "starting briefcased (tcp)");
    app::serve_tcp(addr, state).await?;
    Ok(())
}

fn resolve_data_dir(cli: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(p) = cli {
        return Ok(p.to_path_buf());
    }

    let proj = ProjectDirs::from("com", "briefcase", "credential-briefcase")
        .context("resolve platform data dir")?;
    Ok(proj.data_local_dir().to_path_buf())
}

fn load_or_create_auth_token(path: &Path) -> anyhow::Result<String> {
    if path.exists() {
        let tok = std::fs::read_to_string(path)
            .with_context(|| format!("read auth token {}", path.display()))?;
        return Ok(tok.trim().to_string());
    }

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let tok = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    std::fs::write(path, format!("{tok}\n"))
        .with_context(|| format!("write auth token {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", path.display()))?;
    }

    Ok(tok)
}

async fn open_secret_store(
    data_dir: &Path,
    backend_opt: Option<&str>,
) -> anyhow::Result<std::sync::Arc<dyn briefcase_secrets::SecretStore>> {
    let passphrase = std::env::var("BRIEFCASE_MASTER_PASSPHRASE").ok();

    let kind = match backend_opt {
        Some("keyring") => SecretStoreKind::Keyring,
        Some("file") => SecretStoreKind::File,
        Some("memory") => SecretStoreKind::Memory,
        Some(other) => anyhow::bail!("unknown BRIEFCASE_SECRET_BACKEND: {other}"),
        None => {
            if passphrase.is_some() {
                SecretStoreKind::File
            } else {
                SecretStoreKind::Keyring
            }
        }
    };

    let store = briefcase_secrets::open_secret_store(SecretStoreOptions {
        kind,
        data_dir: data_dir.to_path_buf(),
        passphrase,
    })
    .await?;
    Ok(store)
}
