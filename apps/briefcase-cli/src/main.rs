use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use briefcase_core::{ApprovalKind, ToolCall, ToolCallContext};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use rand::Rng as _;
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

    /// Override the Windows named pipe path (Windows only), e.g. `\\\\.\\pipe\\briefcased-...`.
    #[cfg(windows)]
    #[arg(long, env = "BRIEFCASE_DAEMON_NAMED_PIPE")]
    named_pipe: Option<String>,

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
    Diagnostics {
        #[command(subcommand)]
        cmd: DiagnosticsCommand,
    },
    ControlPlane {
        #[command(subcommand)]
        cmd: ControlPlaneCommand,
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
enum DiagnosticsCommand {
    Check,
    /// Run a long-running tool-call loop and report availability/latency stats (soak helper).
    Soak {
        /// Total runtime for the soak loop.
        #[arg(long, default_value_t = 60)]
        duration_secs: u64,
        /// Target interval between iterations (sleeps if the tool call returns faster).
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
        /// Tool id to call each iteration.
        #[arg(long, default_value = "echo")]
        tool: String,
        /// Tool args as JSON. If omitted, uses a safe default for known tools.
        #[arg(long)]
        args_json: Option<String>,
        /// Optional output path for a machine-readable JSON report.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Print progress every N seconds (0 disables).
        #[arg(long, default_value_t = 60)]
        progress_every_secs: u64,
    },
}

#[derive(Debug, Subcommand)]
enum ControlPlaneCommand {
    Status,
    Enroll {
        base_url: String,
        device_name: String,
        /// Admin bearer token for the control plane. Prefer setting `BRIEFCASE_CONTROL_PLANE_ADMIN_TOKEN`
        /// to avoid leaking it in shell history.
        #[arg(long, env = "BRIEFCASE_CONTROL_PLANE_ADMIN_TOKEN")]
        admin_token: Option<String>,
        /// Read admin token from stdin (useful for piping).
        #[arg(long)]
        admin_token_stdin: bool,
    },
    Sync,
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
    OauthRevoke {
        #[arg(long, default_value = "demo")]
        id: String,
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
    OauthRevoke {
        id: String,
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
            #[cfg(windows)]
            {
                let pipe_name = args
                    .named_pipe
                    .unwrap_or_else(|| briefcase_api::default_named_pipe_name(&auth_token));
                DaemonEndpoint::NamedPipe { pipe_name }
            }
            #[cfg(all(not(unix), not(windows)))]
            {
                anyhow::bail!("no default IPC transport on this platform; set --daemon-base-url");
            }
        }
    };

    let client = BriefcaseClient::new(endpoint, auth_token);

    match args.cmd {
        Command::Diagnostics { cmd } => handle_diagnostics(&client, cmd).await?,
        cmd => {
            client.health().await.context("connect to daemon")?;
            match cmd {
                Command::Tools { cmd } => handle_tools(&client, cmd).await?,
                Command::Identity { cmd } => handle_identity(&client, cmd).await?,
                Command::Diagnostics { .. } => unreachable!("handled above"),
                Command::ControlPlane { cmd } => handle_control_plane(&client, cmd).await?,
                Command::Providers { cmd } => handle_providers(&client, cmd).await?,
                Command::Mcp { cmd } => handle_mcp(&client, cmd).await?,
                Command::Budgets { cmd } => handle_budgets(&client, cmd).await?,
                Command::Approvals { cmd } => handle_approvals(&client, cmd).await?,
                Command::Receipts { cmd } => handle_receipts(&client, cmd).await?,
            }
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TriageStatus {
    Green,
    Yellow,
    Red,
}

impl TriageStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Red => "red",
        }
    }

    fn worst(self, other: Self) -> Self {
        use TriageStatus::*;
        match (self, other) {
            (Red, _) | (_, Red) => Red,
            (Yellow, _) | (_, Yellow) => Yellow,
            (Green, Green) => Green,
        }
    }
}

fn print_check(name: &str, status: TriageStatus, detail: &str, hint: Option<&str>) {
    println!("{}: {} ({})", name, status.as_str(), detail);
    if let Some(h) = hint {
        println!("hint: {}", h);
    }
}

async fn handle_diagnostics(
    client: &BriefcaseClient,
    cmd: DiagnosticsCommand,
) -> anyhow::Result<()> {
    match cmd {
        DiagnosticsCommand::Check => {
            let mut overall = TriageStatus::Green;

            let health_ok = match client.health().await {
                Ok(()) => {
                    print_check("daemon", TriageStatus::Green, "reachable", None);
                    true
                }
                Err(e) => {
                    overall = overall.worst(TriageStatus::Red);
                    print_check(
                        "daemon",
                        TriageStatus::Red,
                        &format!("unreachable: {e}"),
                        Some(
                            "ensure briefcased is running and BRIEFCASE_* endpoint/auth settings are correct",
                        ),
                    );
                    println!("overall: {}", overall.as_str());
                    return Ok(());
                }
            };
            debug_assert!(health_ok);

            // Identity/profile.
            match (client.identity().await, client.profile().await) {
                (Ok(id), Ok(profile)) => {
                    let mut st = TriageStatus::Green;
                    let mut hint = None;
                    if profile.mode != briefcase_core::ProfileMode::Ga {
                        st = TriageStatus::Yellow;
                        hint =
                            Some("set BRIEFCASE_PROFILE_MODE=ga for strict production enforcement");
                    } else if !profile.strict_enforcement {
                        st = TriageStatus::Red;
                        hint = Some(
                            "daemon is in ga mode but strict_enforcement=false; this should not happen",
                        );
                    }
                    overall = overall.worst(st);
                    print_check(
                        "profile",
                        st,
                        &format!(
                            "did={} mode={} compatibility_profile={} strict_enforcement={}",
                            id.did,
                            profile.mode.as_str(),
                            profile.compatibility_profile,
                            profile.strict_enforcement
                        ),
                        hint,
                    );
                }
                (id_res, prof_res) => {
                    overall = overall.worst(TriageStatus::Red);
                    let id_err = id_res.err().map(|e| e.to_string()).unwrap_or_default();
                    let prof_err = prof_res.err().map(|e| e.to_string()).unwrap_or_default();
                    print_check(
                        "profile",
                        TriageStatus::Red,
                        &format!(
                            "failed to query identity/profile: identity={id_err} profile={prof_err}"
                        ),
                        Some("verify BRIEFCASE_AUTH_TOKEN and daemon version compatibility"),
                    );
                }
            }

            // Diagnostics.
            match client.compat_diagnostics().await {
                Ok(diag) => {
                    let ok = diag.checks.iter().filter(|c| c.ok).count();
                    let total = diag.checks.len();
                    let st = if ok == total {
                        TriageStatus::Green
                    } else if diag.mode == briefcase_core::ProfileMode::Ga {
                        TriageStatus::Red
                    } else {
                        TriageStatus::Yellow
                    };
                    overall = overall.worst(st);
                    print_check(
                        "compat",
                        st,
                        &format!(
                            "mode={} profile={} checks_ok={}/{}",
                            diag.mode.as_str(),
                            diag.compatibility_profile,
                            ok,
                            total
                        ),
                        None,
                    );
                    for c in diag.checks.iter().filter(|c| !c.ok) {
                        println!("compat_failed: {} ({})", c.name, c.detail);
                    }
                }
                Err(e) => {
                    overall = overall.worst(TriageStatus::Red);
                    print_check(
                        "compat",
                        TriageStatus::Red,
                        &format!("failed: {e}"),
                        Some("upgrade/downgrade daemon/cli to compatible versions"),
                    );
                }
            }

            match client.security_diagnostics().await {
                Ok(diag) => {
                    let ok = diag.checks.iter().filter(|c| c.ok).count();
                    let total = diag.checks.len();
                    let st = if ok == total {
                        TriageStatus::Green
                    } else {
                        TriageStatus::Red
                    };
                    overall = overall.worst(st);
                    print_check(
                        "security",
                        st,
                        &format!(
                            "mode={} profile={} checks_ok={}/{}",
                            diag.mode.as_str(),
                            diag.compatibility_profile,
                            ok,
                            total
                        ),
                        None,
                    );
                    for c in diag.checks.iter().filter(|c| !c.ok) {
                        println!("security_failed: {} ({})", c.name, c.detail);
                    }
                }
                Err(e) => {
                    overall = overall.worst(TriageStatus::Red);
                    print_check(
                        "security",
                        TriageStatus::Red,
                        &format!("failed: {e}"),
                        Some("upgrade/downgrade daemon/cli to compatible versions"),
                    );
                }
            }

            // Control plane.
            match client.control_plane_status().await {
                Ok(st) => {
                    use briefcase_api::types::ControlPlaneStatusResponse::*;
                    match st {
                        NotEnrolled => {
                            overall = overall.worst(TriageStatus::Yellow);
                            print_check(
                                "control_plane",
                                TriageStatus::Yellow,
                                "not enrolled",
                                Some(
                                    "run: briefcase control-plane enroll <base_url> <device_name> --admin-token ...",
                                ),
                            );
                        }
                        Enrolled {
                            last_error,
                            base_url,
                            device_id,
                            ..
                        } => {
                            let (triage, hint) = if let Some(err) = last_error.as_deref()
                                && !err.trim().is_empty()
                            {
                                (
                                    TriageStatus::Red,
                                    Some(
                                        "run: briefcase control-plane sync; check control plane connectivity and signing key config",
                                    ),
                                )
                            } else {
                                (TriageStatus::Green, None)
                            };
                            overall = overall.worst(triage);
                            print_check(
                                "control_plane",
                                triage,
                                &format!("enrolled base_url={} device_id={}", base_url, device_id),
                                hint,
                            );
                        }
                    }
                }
                Err(e) => {
                    overall = overall.worst(TriageStatus::Red);
                    print_check(
                        "control_plane",
                        TriageStatus::Red,
                        &format!("failed: {e}"),
                        None,
                    );
                }
            }

            // Providers.
            match client.list_providers().await {
                Ok(resp) => {
                    let mut st = TriageStatus::Green;
                    let mut hint = None;
                    if resp.providers.is_empty() {
                        st = TriageStatus::Yellow;
                        hint = Some("add a provider: briefcase providers upsert <id> <base_url>");
                    } else if resp
                        .providers
                        .iter()
                        .all(|p| !p.has_oauth_refresh && !p.has_vc)
                    {
                        st = TriageStatus::Yellow;
                        hint = Some(
                            "authorize or fetch VC: briefcase providers oauth-login --id <id> / briefcase providers vc-fetch --id <id>",
                        );
                    }
                    overall = overall.worst(st);
                    print_check(
                        "providers",
                        st,
                        &format!("count={}", resp.providers.len()),
                        hint,
                    );
                    for p in resp.providers {
                        println!(
                            "provider: id={} base_url={} oauth={} vc={} vc_expires_at={}",
                            p.id,
                            p.base_url,
                            p.has_oauth_refresh,
                            p.has_vc,
                            p.vc_expires_at_rfc3339.as_deref().unwrap_or("-"),
                        );
                    }
                }
                Err(e) => {
                    overall = overall.worst(TriageStatus::Red);
                    print_check(
                        "providers",
                        TriageStatus::Red,
                        &format!("failed: {e}"),
                        None,
                    );
                }
            }

            // MCP servers.
            match client.list_mcp_servers().await {
                Ok(resp) => {
                    print_check(
                        "mcp_servers",
                        TriageStatus::Green,
                        &format!("count={}", resp.servers.len()),
                        None,
                    );
                    for s in resp.servers {
                        println!(
                            "mcp_server: id={} endpoint_url={} oauth={}",
                            s.id, s.endpoint_url, s.has_oauth_refresh
                        );
                    }
                }
                Err(e) => {
                    overall = overall.worst(TriageStatus::Red);
                    print_check(
                        "mcp_servers",
                        TriageStatus::Red,
                        &format!("failed: {e}"),
                        None,
                    );
                }
            }

            println!("overall: {}", overall.as_str());
        }
        DiagnosticsCommand::Soak {
            duration_secs,
            interval_ms,
            tool,
            args_json,
            out,
            progress_every_secs,
        } => {
            // This is an operator/admin tool. It should not print raw secrets. The auth token is
            // used by the client but never displayed here.
            let args = if let Some(s) = args_json.as_deref() {
                serde_json::from_str::<serde_json::Value>(s).context("parse --args-json")?
            } else {
                match tool.as_str() {
                    "echo" => serde_json::json!({ "text": "soak" }),
                    "quote" => serde_json::json!({ "symbol": "TEST" }),
                    _ => serde_json::json!({}),
                }
            };

            let run_for = Duration::from_secs(duration_secs);
            let interval = Duration::from_millis(interval_ms);
            let started = Instant::now();
            let deadline = started + run_for;

            const SAMPLE_CAP: usize = 50_000;
            let mut sample_ms: Vec<f64> = Vec::with_capacity(SAMPLE_CAP);
            let mut rng = rand::rng();
            let mut seen: u64 = 0;

            let mut iters: u64 = 0;
            let mut ok: u64 = 0;
            let mut denied: u64 = 0;
            let mut approval_required: u64 = 0;
            let mut tool_error: u64 = 0;
            let mut other_error: u64 = 0;
            let mut daemon_error_codes: std::collections::BTreeMap<String, u64> =
                std::collections::BTreeMap::new();

            let mut min_ms: Option<f64> = None;
            let mut max_ms: Option<f64> = None;
            let mut sum_ms: f64 = 0.0;

            let mut last_progress = Instant::now();

            while Instant::now() < deadline {
                let iter_start = Instant::now();

                let call = ToolCall {
                    tool_id: tool.clone(),
                    args: args.clone(),
                    context: ToolCallContext::new(),
                    approval_token: None,
                };

                let resp = client.call_tool(CallToolRequest { call }).await;
                let elapsed = iter_start.elapsed();

                // Latency tracking (bounded memory via reservoir sampling).
                let ms = elapsed.as_secs_f64() * 1000.0;
                sum_ms += ms;
                min_ms = Some(min_ms.map_or(ms, |v| v.min(ms)));
                max_ms = Some(max_ms.map_or(ms, |v| v.max(ms)));

                seen += 1;
                if sample_ms.len() < SAMPLE_CAP {
                    sample_ms.push(ms);
                } else {
                    // Reservoir sampling: replace a random entry with decreasing probability.
                    let j = rng.random_range(0..seen);
                    if (j as usize) < SAMPLE_CAP {
                        sample_ms[j as usize] = ms;
                    }
                }

                iters += 1;

                match resp {
                    Ok(CallToolResponse::Ok { .. }) => ok += 1,
                    Ok(CallToolResponse::Denied { .. }) => denied += 1,
                    Ok(CallToolResponse::ApprovalRequired { .. }) => approval_required += 1,
                    Ok(CallToolResponse::Error { .. }) => tool_error += 1,
                    Err(briefcase_api::BriefcaseClientError::Daemon { code, .. }) => {
                        *daemon_error_codes.entry(code).or_insert(0) += 1;
                    }
                    Err(_) => other_error += 1,
                }

                if progress_every_secs > 0
                    && last_progress.elapsed() >= Duration::from_secs(progress_every_secs)
                {
                    last_progress = Instant::now();
                    let elapsed_s = started.elapsed().as_secs_f64();
                    let mean_ms = if iters > 0 {
                        sum_ms / iters as f64
                    } else {
                        0.0
                    };
                    println!(
                        "progress: elapsed_secs={:.1} iters={} ok={} denied={} approval_required={} tool_error={} daemon_error={} other_error={} mean_ms={:.2}",
                        elapsed_s,
                        iters,
                        ok,
                        denied,
                        approval_required,
                        tool_error,
                        daemon_error_codes.values().sum::<u64>(),
                        other_error,
                        mean_ms
                    );
                }

                // Maintain a steady call rate when possible.
                if let Some(remaining) = interval.checked_sub(elapsed) {
                    tokio::time::sleep(remaining).await;
                }
            }

            #[derive(Debug, serde::Serialize)]
            struct SoakReport {
                tool_id: String,
                duration_secs: u64,
                interval_ms: u64,
                iters: u64,
                ok: u64,
                denied: u64,
                approval_required: u64,
                tool_error: u64,
                daemon_error_codes: std::collections::BTreeMap<String, u64>,
                other_error: u64,
                latency_min_ms: Option<f64>,
                latency_max_ms: Option<f64>,
                latency_mean_ms: Option<f64>,
                latency_p50_ms: Option<f64>,
                latency_p95_ms: Option<f64>,
                latency_p99_ms: Option<f64>,
                generated_at_rfc3339: String,
            }

            fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
                if sorted.is_empty() {
                    return None;
                }
                let p = p.clamp(0.0, 1.0);
                let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
                sorted.get(idx).copied()
            }

            sample_ms.sort_by(|a, b| a.total_cmp(b));
            let mean_ms = if iters > 0 {
                Some(sum_ms / iters as f64)
            } else {
                None
            };

            let report = SoakReport {
                tool_id: tool,
                duration_secs,
                interval_ms,
                iters,
                ok,
                denied,
                approval_required,
                tool_error,
                daemon_error_codes,
                other_error,
                latency_min_ms: min_ms,
                latency_max_ms: max_ms,
                latency_mean_ms: mean_ms,
                latency_p50_ms: percentile(&sample_ms, 0.50),
                latency_p95_ms: percentile(&sample_ms, 0.95),
                latency_p99_ms: percentile(&sample_ms, 0.99),
                generated_at_rfc3339: chrono::Utc::now().to_rfc3339(),
            };

            println!("{}", serde_json::to_string_pretty(&report)?);
            if let Some(out_path) = out.as_deref() {
                std::fs::write(out_path, serde_json::to_vec_pretty(&report)?)
                    .with_context(|| format!("write report {}", out_path.display()))?;
            }
        }
    }

    Ok(())
}

async fn handle_control_plane(
    client: &BriefcaseClient,
    cmd: ControlPlaneCommand,
) -> anyhow::Result<()> {
    match cmd {
        ControlPlaneCommand::Status => {
            let st = client.control_plane_status().await?;
            println!("{}", serde_json::to_string_pretty(&st)?);
        }
        ControlPlaneCommand::Enroll {
            base_url,
            device_name,
            admin_token,
            admin_token_stdin,
        } => {
            let admin_token = match (admin_token, admin_token_stdin) {
                (Some(t), false) => t,
                (None, true) => {
                    let mut s = String::new();
                    std::io::stdin().read_line(&mut s)?;
                    s.trim().to_string()
                }
                (Some(_), true) => {
                    anyhow::bail!("provide either --admin-token or --admin-token-stdin")
                }
                (None, false) => anyhow::bail!(
                    "missing admin token (use --admin-token, --admin-token-stdin, or BRIEFCASE_CONTROL_PLANE_ADMIN_TOKEN)"
                ),
            };

            let st = client
                .control_plane_enroll(briefcase_api::types::ControlPlaneEnrollRequest {
                    base_url,
                    admin_token,
                    device_name,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&st)?);
        }
        ControlPlaneCommand::Sync => {
            let st = client.control_plane_sync().await?;
            println!("{}", serde_json::to_string_pretty(&st)?);
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
        ProvidersCommand::OauthRevoke { id } => {
            let r = client.revoke_provider_oauth(&id).await?;
            println!(
                "provider_oauth_revoke: provider={} had_refresh_token={} remote_attempted={} remote_ok={}",
                r.provider_id,
                r.had_refresh_token,
                r.remote_revocation_attempted,
                r.remote_revocation_succeeded
            );
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
            McpServersCommand::OauthRevoke { id } => {
                let r = client.revoke_mcp_oauth(&id).await?;
                println!(
                    "mcp_oauth_revoke: server={} had_refresh_token={} remote_attempted={} remote_ok={}",
                    r.server_id,
                    r.had_refresh_token,
                    r.remote_revocation_attempted,
                    r.remote_revocation_succeeded
                );
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
                let kind = match a.kind {
                    ApprovalKind::Local => "local",
                    ApprovalKind::MobileSigner => "mobile_signer",
                };
                println!(
                    "{} tool={} kind={} reason={} expires_at={}",
                    a.id,
                    a.tool_id,
                    kind,
                    a.reason,
                    a.expires_at.to_rfc3339()
                );
            }
        }
        ApprovalsCommand::Approve { id } => {
            if let Some(a) = client
                .list_approvals()
                .await?
                .approvals
                .into_iter()
                .find(|a| a.id == id)
                && matches!(a.kind, ApprovalKind::MobileSigner)
            {
                println!(
                    "approval {} requires a paired mobile signer; approve it from the mobile signer app",
                    a.id
                );
                return Ok(());
            }
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
