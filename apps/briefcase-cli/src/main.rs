use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use axum::Router;
use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use base64::Engine as _;
use briefcase_api::types::{
    CallToolRequest, CallToolResponse, McpOAuthExchangeRequest, McpOAuthStartRequest,
    OAuthExchangeRequest,
};
use briefcase_api::{BriefcaseClient, DaemonEndpoint};
use briefcase_core::{ToolCall, ToolCallContext};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "briefcase", version, about = "Credential Briefcase CLI")]
struct Args {
    /// Directory for runtime state (auth token, socket).
    #[arg(long, env = "BRIEFCASE_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Use a TCP daemon endpoint, e.g. `http://127.0.0.1:3000`.
    #[arg(long, env = "BRIEFCASE_DAEMON_BASE_URL")]
    daemon_base_url: Option<String>,

    /// Override the unix socket path (Unix only).
    #[arg(long, env = "BRIEFCASE_DAEMON_UNIX_SOCKET")]
    unix_socket: Option<PathBuf>,

    /// Override the daemon auth token (otherwise read from <data_dir>/auth_token).
    #[arg(long, env = "BRIEFCASE_AUTH_TOKEN")]
    auth_token: Option<String>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Tools {
        #[command(subcommand)]
        cmd: ToolsCommand,
    },
    Identity {
        #[command(subcommand)]
        cmd: IdentityCommand,
    },
    Providers {
        #[command(subcommand)]
        cmd: ProvidersCommand,
    },
    Mcp {
        #[command(subcommand)]
        cmd: McpCommand,
    },
    Budgets {
        #[command(subcommand)]
        cmd: BudgetsCommand,
    },
    Approvals {
        #[command(subcommand)]
        cmd: ApprovalsCommand,
    },
    Receipts {
        #[command(subcommand)]
        cmd: ReceiptsCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ToolsCommand {
    List,
    Call {
        tool: String,
        /// Tool args as JSON. Example: `{\"text\":\"hello\"}`.
        #[arg(long)]
        args_json: String,
        /// Optional approval token (UUID) previously returned by `approvals approve`.
        #[arg(long)]
        approval_token: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    Show,
}

#[derive(Debug, Subcommand)]
enum ProvidersCommand {
    List,
    Upsert {
        id: String,
        base_url: String,
    },
    Delete {
        id: String,
    },
    OauthLogin {
        #[arg(long, default_value = "demo")]
        id: String,
        #[arg(long, default_value = "briefcase-cli")]
        client_id: String,
    },
    VcFetch {
        #[arg(long, default_value = "demo")]
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    Servers {
        #[command(subcommand)]
        cmd: McpServersCommand,
    },
}

#[derive(Debug, Subcommand)]
enum McpServersCommand {
    List,
    Upsert {
        id: String,
        endpoint_url: String,
    },
    Delete {
        id: String,
    },
    OauthLogin {
        id: String,
        #[arg(long, default_value = "briefcase-cli")]
        client_id: String,
        #[arg(long)]
        scope: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum BudgetsCommand {
    List,
    Set {
        category: String,
        /// Daily budget in USD (example: `3.0` for $3/day).
        #[arg(long)]
        daily_limit_usd: f64,
    },
}

#[derive(Debug, Subcommand)]
enum ApprovalsCommand {
    List,
    Approve { id: Uuid },
}

#[derive(Debug, Subcommand)]
enum ReceiptsCommand {
    List,
    Verify,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .json()
        .init();

    let args = Args::parse();
    let data_dir = resolve_data_dir(args.data_dir.as_deref())?;

    let auth_token = match args.auth_token {
        Some(t) => t,
        None => std::fs::read_to_string(data_dir.join("auth_token"))
            .context("read daemon auth_token")?
            .trim()
            .to_string(),
    };

    let endpoint = match args.daemon_base_url {
        Some(base_url) => DaemonEndpoint::Tcp { base_url },
        None => {
            #[cfg(unix)]
            {
                let socket_path = args
                    .unix_socket
                    .unwrap_or_else(|| data_dir.join("briefcased.sock"));
                DaemonEndpoint::Unix { socket_path }
            }
            #[cfg(not(unix))]
            {
                anyhow::bail!("unix sockets not supported; set --daemon-base-url");
            }
        }
    };

    let client = BriefcaseClient::new(endpoint, auth_token);
    client.health().await.context("connect to daemon")?;

    match args.cmd {
        Command::Tools { cmd } => handle_tools(&client, cmd).await?,
        Command::Identity { cmd } => handle_identity(&client, cmd).await?,
        Command::Providers { cmd } => handle_providers(&client, cmd).await?,
        Command::Mcp { cmd } => handle_mcp(&client, cmd).await?,
        Command::Budgets { cmd } => handle_budgets(&client, cmd).await?,
        Command::Approvals { cmd } => handle_approvals(&client, cmd).await?,
        Command::Receipts { cmd } => handle_receipts(&client, cmd).await?,
    }

    Ok(())
}

async fn handle_identity(client: &BriefcaseClient, cmd: IdentityCommand) -> anyhow::Result<()> {
    match cmd {
        IdentityCommand::Show => {
            let id = client.identity().await?;
            println!("{}", id.did);
        }
    }
    Ok(())
}

async fn handle_providers(client: &BriefcaseClient, cmd: ProvidersCommand) -> anyhow::Result<()> {
    match cmd {
        ProvidersCommand::List => {
            let providers = client.list_providers().await?.providers;
            for p in providers {
                println!(
                    "{} base_url={} oauth={} vc={} vc_expires_at={}",
                    p.id,
                    p.base_url,
                    p.has_oauth_refresh,
                    p.has_vc,
                    p.vc_expires_at_rfc3339.as_deref().unwrap_or("-")
                );
            }
        }
        ProvidersCommand::Upsert { id, base_url } => {
            let p = client.upsert_provider(&id, base_url).await?;
            println!(
                "provider_upsert: id={} base_url={} oauth={} vc={}",
                p.id, p.base_url, p.has_oauth_refresh, p.has_vc
            );
        }
        ProvidersCommand::Delete { id } => {
            let r = client.delete_provider(&id).await?;
            println!("provider_delete: id={}", r.provider_id);
        }
        ProvidersCommand::OauthLogin { id, client_id } => {
            oauth_login(client, &id, &client_id).await?;
            println!("oauth_login: ok provider={id}");
        }
        ProvidersCommand::VcFetch { id } => {
            let r = client.fetch_vc(&id).await?;
            println!(
                "vc_fetch: ok provider={} expires_at={}",
                r.provider_id, r.expires_at_rfc3339
            );
        }
    }
    Ok(())
}

async fn handle_mcp(client: &BriefcaseClient, cmd: McpCommand) -> anyhow::Result<()> {
    match cmd {
        McpCommand::Servers { cmd } => match cmd {
            McpServersCommand::List => {
                let servers = client.list_mcp_servers().await?.servers;
                for s in servers {
                    println!("{} endpoint_url={}", s.id, s.endpoint_url);
                }
            }
            McpServersCommand::Upsert { id, endpoint_url } => {
                let s = client.upsert_mcp_server(&id, endpoint_url).await?;
                println!(
                    "mcp_server_upsert: id={} endpoint_url={}",
                    s.id, s.endpoint_url
                );
            }
            McpServersCommand::Delete { id } => {
                let r = client.delete_mcp_server(&id).await?;
                println!("mcp_server_delete: id={}", r.server_id);
            }
            McpServersCommand::OauthLogin {
                id,
                client_id,
                scope,
            } => {
                mcp_oauth_login(client, &id, &client_id, scope.as_deref()).await?;
                println!("mcp_oauth_login: ok server={id}");
            }
        },
    }
    Ok(())
}

async fn handle_budgets(client: &BriefcaseClient, cmd: BudgetsCommand) -> anyhow::Result<()> {
    match cmd {
        BudgetsCommand::List => {
            let rows = client.list_budgets().await?.budgets;
            for b in rows {
                let usd = b.daily_limit_microusd as f64 / 1_000_000.0;
                println!(
                    "{} daily_limit_usd={:.6} (microusd={})",
                    b.category, usd, b.daily_limit_microusd
                );
            }
        }
        BudgetsCommand::Set {
            category,
            daily_limit_usd,
        } => {
            if !daily_limit_usd.is_finite() || daily_limit_usd < 0.0 {
                anyhow::bail!("daily_limit_usd must be a non-negative finite number");
            }
            let microusd = (daily_limit_usd * 1_000_000.0).round() as i64;
            let b = client.set_budget(&category, microusd).await?;
            println!(
                "budget_set: category={} daily_limit_usd={:.6} (microusd={})",
                b.category,
                b.daily_limit_microusd as f64 / 1_000_000.0,
                b.daily_limit_microusd
            );
        }
    }
    Ok(())
}

async fn handle_tools(client: &BriefcaseClient, cmd: ToolsCommand) -> anyhow::Result<()> {
    match cmd {
        ToolsCommand::List => {
            let tools = client.list_tools().await?.tools;
            for t in tools {
                println!("{} - {}", t.id, t.description);
            }
        }
        ToolsCommand::Call {
            tool,
            args_json,
            approval_token,
        } => {
            let args: serde_json::Value = serde_json::from_str(&args_json)?;
            let call = ToolCall {
                tool_id: tool,
                args,
                context: ToolCallContext::new(),
                approval_token,
            };
            let resp = client.call_tool(CallToolRequest { call }).await?;
            match resp {
                CallToolResponse::Ok { result } => {
                    println!("{}", serde_json::to_string_pretty(&result.content)?);
                    println!(
                        "provenance: source={} cost_usd={:?} receipt_id={}",
                        result.provenance.source,
                        result.provenance.cost_usd,
                        result.provenance.receipt_id
                    );
                }
                CallToolResponse::ApprovalRequired { approval } => {
                    println!(
                        "approval_required: tool={} reason={} id={}",
                        approval.tool_id, approval.reason, approval.id
                    );
                }
                CallToolResponse::Denied { reason } => {
                    println!("denied: {reason}");
                }
                CallToolResponse::Error { message } => {
                    println!("error: {message}");
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct CallbackState {
    tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<OAuthCallback>>>>,
}

#[derive(Debug)]
struct OAuthCallback {
    code: String,
    state: String,
}

#[derive(Debug, serde::Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

async fn oauth_login(
    client: &BriefcaseClient,
    provider_id: &str,
    oauth_client_id: &str,
) -> anyhow::Result<()> {
    let providers = client.list_providers().await?.providers;
    let p = providers
        .iter()
        .find(|p| p.id == provider_id)
        .context("unknown provider id")?;
    let base_url = p.base_url.clone();

    let (tx, rx) = tokio::sync::oneshot::channel::<OAuthCallback>();
    let st = CallbackState {
        tx: Arc::new(Mutex::new(Some(tx))),
    };

    async fn callback(
        State(st): State<CallbackState>,
        Query(q): Query<CallbackQuery>,
    ) -> Html<String> {
        if let Some(tx) = st.tx.lock().await.take() {
            let _ = tx.send(OAuthCallback {
                code: q.code,
                state: q.state,
            });
        }
        Html(
            "<h1>OAuth complete</h1><p>You can close this tab and return to the terminal.</p>"
                .to_string(),
        )
    }

    let app = Router::new()
        .route("/callback", get(callback))
        .with_state(st);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let redirect_uri = format!("http://127.0.0.1:{}/callback", addr.port());

    // PKCE
    let mut verifier_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut verifier_bytes);
    let code_verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifier_bytes);
    let challenge = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);

    let state = Uuid::new_v4().to_string();
    let mut u = Url::parse(&format!("{base_url}/oauth/authorize"))?;
    u.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", oauth_client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("state", &state)
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256");

    println!("Open this URL in your browser:\n\n{}\n", u.as_str());

    let cb = tokio::time::timeout(std::time::Duration::from_secs(180), rx)
        .await
        .context("oauth callback timed out")??;

    handle.abort();

    if cb.state != state {
        anyhow::bail!("oauth state mismatch");
    }

    client
        .oauth_exchange(
            provider_id,
            OAuthExchangeRequest {
                code: cb.code,
                redirect_uri,
                client_id: oauth_client_id.to_string(),
                code_verifier,
            },
        )
        .await?;

    Ok(())
}

async fn mcp_oauth_login(
    client: &BriefcaseClient,
    server_id: &str,
    oauth_client_id: &str,
    scope: Option<&str>,
) -> anyhow::Result<()> {
    let (tx, rx) = tokio::sync::oneshot::channel::<OAuthCallback>();
    let st = CallbackState {
        tx: Arc::new(Mutex::new(Some(tx))),
    };

    async fn callback(
        State(st): State<CallbackState>,
        Query(q): Query<CallbackQuery>,
    ) -> Html<String> {
        if let Some(tx) = st.tx.lock().await.take() {
            let _ = tx.send(OAuthCallback {
                code: q.code,
                state: q.state,
            });
        }
        Html(
            "<h1>OAuth complete</h1><p>You can close this tab and return to the terminal.</p>"
                .to_string(),
        )
    }

    let app = Router::new()
        .route("/callback", get(callback))
        .with_state(st);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let redirect_uri = format!("http://127.0.0.1:{}/callback", addr.port());

    let start = client
        .mcp_oauth_start(
            server_id,
            McpOAuthStartRequest {
                client_id: oauth_client_id.to_string(),
                redirect_uri: redirect_uri.clone(),
                scope: scope.map(|s| s.to_string()),
            },
        )
        .await?;

    println!(
        "Open this URL in your browser:\n\n{}\n",
        start.authorization_url
    );

    let cb = tokio::time::timeout(std::time::Duration::from_secs(180), rx)
        .await
        .context("oauth callback timed out")??;

    handle.abort();

    if cb.state != start.state {
        anyhow::bail!("oauth state mismatch");
    }

    client
        .mcp_oauth_exchange(
            server_id,
            McpOAuthExchangeRequest {
                code: cb.code,
                state: cb.state,
            },
        )
        .await?;

    Ok(())
}

async fn handle_approvals(client: &BriefcaseClient, cmd: ApprovalsCommand) -> anyhow::Result<()> {
    match cmd {
        ApprovalsCommand::List => {
            let approvals = client.list_approvals().await?.approvals;
            for a in approvals {
                println!(
                    "{} tool={} reason={} expires_at={}",
                    a.id,
                    a.tool_id,
                    a.reason,
                    a.expires_at.to_rfc3339()
                );
            }
        }
        ApprovalsCommand::Approve { id } => {
            let r = client.approve(&id).await?;
            println!("approved: id={} token={}", r.approval_id, r.approval_token);
        }
    }
    Ok(())
}

async fn handle_receipts(client: &BriefcaseClient, cmd: ReceiptsCommand) -> anyhow::Result<()> {
    match cmd {
        ReceiptsCommand::List => {
            let receipts = client.list_receipts().await?.receipts;
            for r in receipts {
                println!(
                    "{} ts={} hash={} kind={}",
                    r.id,
                    r.ts.to_rfc3339(),
                    r.hash_hex,
                    r.event
                        .get("kind")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                );
            }
        }
        ReceiptsCommand::Verify => {
            let r = client.verify_receipts().await?;
            if r.ok {
                println!("verify: ok");
            } else {
                println!("verify: failed");
            }
        }
    }
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
