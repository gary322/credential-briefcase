use std::path::{Path, PathBuf};

use anyhow::Context as _;
use briefcase_api::{BriefcaseClient, DaemonEndpoint};
use clap::Parser;
use directories::ProjectDirs;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "briefcase-native-messaging-host",
    version,
    about = "Native messaging host for Credential Briefcase browser extension"
)]
struct Args {
    /// Directory used by `briefcased` to store runtime state (auth token, socket).
    ///
    /// Defaults to the same platform-specific directory used by the daemon.
    #[arg(long, env = "BRIEFCASE_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Path to the daemon auth token file.
    ///
    /// Default: `<data_dir>/auth_token`.
    #[arg(long, env = "BRIEFCASE_AUTH_TOKEN_PATH")]
    auth_token_path: Option<PathBuf>,

    /// Connect to the daemon over TCP.
    ///
    /// Example: `http://127.0.0.1:8787`
    #[arg(long, env = "BRIEFCASE_TCP_BASE_URL")]
    tcp_base_url: Option<String>,

    /// Connect to the daemon over a Unix domain socket.
    ///
    /// Default (Unix only): `<data_dir>/briefcased.sock`.
    #[cfg(unix)]
    #[arg(long, env = "BRIEFCASE_UNIX_SOCKET")]
    unix_socket: Option<PathBuf>,

    /// Connect to the daemon over a Windows named pipe.
    ///
    /// Default (Windows only): derived from the daemon auth token.
    #[cfg(windows)]
    #[arg(long, env = "BRIEFCASE_NAMED_PIPE")]
    named_pipe: Option<String>,
}

fn resolve_data_dir(cli: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(p) = cli {
        return Ok(p.to_path_buf());
    }
    let proj = ProjectDirs::from("com", "briefcase", "credential-briefcase")
        .context("resolve platform data dir")?;
    Ok(proj.data_local_dir().to_path_buf())
}

fn load_auth_token(path: &Path) -> anyhow::Result<String> {
    let tok = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let tok = tok.trim().to_string();
    if tok.is_empty() {
        anyhow::bail!("auth token is empty");
    }
    Ok(tok)
}

fn resolve_endpoint(
    args: &Args,
    data_dir: &Path,
    auth_token: &str,
) -> anyhow::Result<DaemonEndpoint> {
    let _ = auth_token; // Used for Windows named-pipe defaulting.

    if let Some(base_url) = &args.tcp_base_url {
        return Ok(DaemonEndpoint::Tcp {
            base_url: base_url.clone(),
        });
    }

    #[cfg(unix)]
    {
        if let Some(p) = &args.unix_socket {
            return Ok(DaemonEndpoint::Unix {
                socket_path: p.clone(),
            });
        }
        let default_sock = data_dir.join("briefcased.sock");
        if default_sock.exists() {
            return Ok(DaemonEndpoint::Unix {
                socket_path: default_sock,
            });
        }
    }

    #[cfg(windows)]
    {
        let pipe_name = args
            .named_pipe
            .clone()
            .unwrap_or_else(|| briefcase_api::default_named_pipe_name(auth_token));
        return Ok(DaemonEndpoint::NamedPipe { pipe_name });
    }

    anyhow::bail!(
        "no daemon endpoint configured (set BRIEFCASE_UNIX_SOCKET, BRIEFCASE_TCP_BASE_URL, or BRIEFCASE_NAMED_PIPE)"
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Native messaging protocol uses stdin/stdout. Never log to stdout.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .json()
        .init();

    let args = Args::parse();
    let data_dir = resolve_data_dir(args.data_dir.as_deref())?;
    let auth_token_path = args
        .auth_token_path
        .clone()
        .unwrap_or_else(|| data_dir.join("auth_token"));

    let auth_token = load_auth_token(&auth_token_path)?;
    let endpoint = resolve_endpoint(&args, &data_dir, &auth_token)?;
    let client = BriefcaseClient::new(endpoint, auth_token);

    // Eager check so failures happen before we block waiting for messages.
    client.health().await.context("daemon health")?;

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    native_messaging_host::run_native_messaging_host(&client, &mut stdin, &mut stdout)
        .await
        .context("native messaging loop")?;
    Ok(())
}
