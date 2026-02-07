use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, Request, StatusCode, header::HOST, uri::Authority};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use briefcase_api::{BriefcaseClient, DaemonEndpoint};
use clap::Parser;
use directories::ProjectDirs;
use rand::RngCore as _;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "briefcase-ui",
    version,
    about = "Local approvals + receipts UI"
)]
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

    /// Address to bind the UI server.
    #[arg(long, env = "BRIEFCASE_UI_ADDR", default_value = "127.0.0.1:8787")]
    ui_addr: SocketAddr,
}

#[derive(Clone)]
struct AppState {
    client: BriefcaseClient,
    csrf_token: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hyper=warn".into()),
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

    let csrf_token = random_token_b64url(32);
    let st = AppState { client, csrf_token };

    let app = Router::new()
        .route("/", get(index))
        .route("/api/identity", get(api_identity))
        .route("/api/providers", get(api_providers))
        .route("/api/approvals", get(api_approvals))
        .route("/api/approvals/{id}/approve", post(api_approve))
        .route("/api/receipts", get(api_receipts))
        .layer(TraceLayer::new_for_http())
        // DNS rebinding defense: if a hostile site can cause a browser to treat it as the UI
        // origin (by rebinding to 127.0.0.1), they could read the CSRF token and issue writes.
        .layer(middleware::from_fn(enforce_ui_host_allowlist))
        .with_state(st);

    info!(addr = %args.ui_addr, "briefcase-ui listening");
    let listener = tokio::net::TcpListener::bind(args.ui_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn enforce_ui_host_allowlist(req: Request<axum::body::Body>, next: Next) -> Response {
    // Only accept loopback hosts. If a DNS rebinding attack points a hostname at 127.0.0.1,
    // the browser's Host header would still be the attacker-controlled name and will be rejected.
    let host = req
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if !is_allowed_ui_host(host) {
        return (StatusCode::BAD_REQUEST, "invalid_host").into_response();
    }

    next.run(req).await
}

fn is_allowed_ui_host(host: &str) -> bool {
    let auth: Authority = match host.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Tolerate `localhost.` from some resolvers, and accept bracketed IPv6 literals.
    let h = auth
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    h.eq_ignore_ascii_case("localhost") || h == "127.0.0.1" || h == "::1"
}

async fn index(State(st): State<AppState>) -> Html<String> {
    // Minimal, dependency-free UI. Avoid exposing daemon auth tokens; use server-side proxy.
    let html = format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <meta name="csrf-token" content="{csrf}"/>
    <title>Briefcase</title>
    <style>
      :root {{
        --bg: #0b0e14;
        --panel: #121826;
        --text: #e7edf5;
        --muted: #9fb0c0;
        --accent: #3ee0b0;
        --danger: #ff5b6e;
        --border: rgba(255,255,255,0.09);
        --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      }}
      body {{
        margin: 0;
        font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";
        background: radial-gradient(800px 500px at 20% 0%, rgba(62,224,176,0.12), transparent 50%),
                    radial-gradient(900px 600px at 80% 10%, rgba(255,91,110,0.10), transparent 50%),
                    var(--bg);
        color: var(--text);
      }}
      header {{
        padding: 18px 20px;
        border-bottom: 1px solid var(--border);
        backdrop-filter: blur(10px);
        position: sticky;
        top: 0;
        background: rgba(11,14,20,0.7);
      }}
      h1 {{ font-size: 18px; margin: 0; letter-spacing: 0.02em; }}
      .sub {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
      main {{ max-width: 1080px; margin: 0 auto; padding: 16px; display: grid; gap: 12px; }}
      .grid {{ display: grid; gap: 12px; grid-template-columns: 1fr; }}
      @media (min-width: 960px) {{ .grid {{ grid-template-columns: 1fr 1fr; }} }}
      .card {{
        background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02));
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 14px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.25);
      }}
      .card h2 {{ margin: 0 0 8px; font-size: 14px; color: var(--muted); font-weight: 600; }}
      .row {{ display:flex; align-items: baseline; justify-content: space-between; gap: 10px; }}
      .mono {{ font-family: var(--mono); font-size: 12px; color: var(--muted); }}
      table {{ width: 100%; border-collapse: collapse; }}
      th, td {{ text-align: left; padding: 10px 8px; border-top: 1px solid var(--border); font-size: 13px; }}
      th {{ color: var(--muted); font-weight: 600; }}
      button {{
        background: rgba(62,224,176,0.15);
        color: var(--text);
        border: 1px solid rgba(62,224,176,0.35);
        padding: 8px 10px;
        border-radius: 10px;
        cursor: pointer;
      }}
      button.danger {{
        background: rgba(255,91,110,0.12);
        border-color: rgba(255,91,110,0.35);
      }}
      button:disabled {{
        opacity: 0.6;
        cursor: not-allowed;
      }}
      .pill {{
        display:inline-flex;
        align-items:center;
        gap:6px;
        padding: 4px 8px;
        border-radius: 999px;
        border: 1px solid var(--border);
        color: var(--muted);
        font-size: 12px;
      }}
      .pill.ok {{ border-color: rgba(62,224,176,0.35); color: rgba(62,224,176,0.9); }}
      .pill.no {{ border-color: rgba(255,91,110,0.35); color: rgba(255,91,110,0.9); }}
      .muted {{ color: var(--muted); }}
      a {{ color: var(--accent); text-decoration: none; }}
      a:hover {{ text-decoration: underline; }}
      .err {{ color: var(--danger); font-family: var(--mono); font-size: 12px; }}
    </style>
  </head>
  <body>
    <header>
      <h1>Credential Briefcase</h1>
      <div class="sub">Local approvals, receipts, and provider status</div>
    </header>
    <main>
      <div class="grid">
        <section class="card">
          <div class="row">
            <h2>Identity</h2>
            <span id="identityStatus" class="pill">loading</span>
          </div>
          <div class="mono" id="did">-</div>
        </section>

        <section class="card">
          <div class="row">
            <h2>Providers</h2>
            <button id="refreshBtn">Refresh</button>
          </div>
          <div id="providersErr" class="err"></div>
          <table>
            <thead><tr><th>ID</th><th>OAuth</th><th>VC</th><th class="mono">Base URL</th></tr></thead>
            <tbody id="providersBody"></tbody>
          </table>
          <div class="muted">OAuth login + VC fetch are done via CLI for now.</div>
        </section>
      </div>

      <section class="card">
        <div class="row">
          <h2>Approvals</h2>
          <button id="refreshApprovalsBtn">Refresh</button>
        </div>
        <div id="approvalsErr" class="err"></div>
        <table>
          <thead><tr><th>ID</th><th>Tool</th><th>Reason</th><th>Kind</th><th>Expires</th><th></th></tr></thead>
          <tbody id="approvalsBody"></tbody>
        </table>
      </section>

      <section class="card">
        <div class="row">
          <h2>Receipts (latest)</h2>
          <button id="refreshReceiptsBtn">Refresh</button>
        </div>
        <div id="receiptsErr" class="err"></div>
        <table>
          <thead><tr><th>ID</th><th>TS</th><th class="mono">Hash</th><th>Kind</th></tr></thead>
          <tbody id="receiptsBody"></tbody>
        </table>
      </section>
    </main>

    <script>
      const csrf = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
      const qs = (s) => document.querySelector(s);
      const fmt = (s) => (s ? s : '-');

      async function getJson(path) {{
        const r = await fetch(path, {{ headers: {{ 'accept': 'application/json' }} }});
        if (!r.ok) throw new Error(`${{r.status}} ${{r.statusText}}`);
        return await r.json();
      }}

      async function postJson(path, body) {{
        const r = await fetch(path, {{
          method: 'POST',
          headers: {{
            'content-type': 'application/json',
            'accept': 'application/json',
            'x-csrf-token': csrf,
          }},
          body: JSON.stringify(body || {{}}),
        }});
        if (!r.ok) throw new Error(`${{r.status}} ${{r.statusText}}`);
        return await r.json();
      }}

      async function loadIdentity() {{
        try {{
          const v = await getJson('/api/identity');
          qs('#did').textContent = v.did;
          qs('#identityStatus').textContent = 'ok';
          qs('#identityStatus').className = 'pill ok';
        }} catch (e) {{
          qs('#identityStatus').textContent = 'error';
          qs('#identityStatus').className = 'pill no';
          qs('#did').textContent = e.toString();
        }}
      }}

      async function loadProviders() {{
        qs('#providersErr').textContent = '';
        qs('#providersBody').innerHTML = '';
        try {{
          const v = await getJson('/api/providers');
          for (const p of v.providers) {{
            const tr = document.createElement('tr');
            tr.innerHTML = `
              <td><span class="mono">${{p.id}}</span></td>
              <td><span class="pill ${{p.has_oauth_refresh ? 'ok' : 'no'}}">${{p.has_oauth_refresh ? 'yes' : 'no'}}</span></td>
              <td><span class="pill ${{p.has_vc ? 'ok' : 'no'}}">${{p.has_vc ? 'yes' : 'no'}}</span></td>
              <td class="mono">${{p.base_url}}</td>
            `;
            qs('#providersBody').appendChild(tr);
          }}
        }} catch (e) {{
          qs('#providersErr').textContent = e.toString();
        }}
      }}

      async function loadApprovals() {{
        qs('#approvalsErr').textContent = '';
        qs('#approvalsBody').innerHTML = '';
        try {{
          const v = await getJson('/api/approvals');
          for (const a of v.approvals) {{
            const tr = document.createElement('tr');
            const btn = document.createElement('button');
            const needsSigner = a.kind === 'mobile_signer';
            btn.textContent = needsSigner ? 'Mobile signer required' : 'Approve';
            btn.disabled = needsSigner;
            if (!needsSigner) {{
              btn.onclick = async () => {{
                btn.disabled = true;
                try {{
                  await postJson(`/api/approvals/${{a.id}}/approve`, {{}});
                  await loadApprovals();
                }} catch (e) {{
                  qs('#approvalsErr').textContent = e.toString();
                }} finally {{
                  btn.disabled = false;
                }}
              }};
            }}
            tr.innerHTML = `
              <td class="mono">${{a.id}}</td>
              <td>${{a.tool_id}}</td>
              <td class="muted">${{a.reason}}</td>
              <td><span class="pill ${{a.kind === 'local' ? 'ok' : 'no'}}">${{a.kind}}</span></td>
              <td class="mono">${{a.expires_at}}</td>
              <td></td>
            `;
            tr.children[5].appendChild(btn);
            qs('#approvalsBody').appendChild(tr);
          }}
        }} catch (e) {{
          qs('#approvalsErr').textContent = e.toString();
        }}
      }}

      async function loadReceipts() {{
        qs('#receiptsErr').textContent = '';
        qs('#receiptsBody').innerHTML = '';
        try {{
          const v = await getJson('/api/receipts');
          for (const r of v.receipts) {{
            const kind = (r.event && r.event.kind) ? r.event.kind : 'unknown';
            const tr = document.createElement('tr');
            tr.innerHTML = `
              <td class="mono">${{r.id}}</td>
              <td class="mono">${{r.ts}}</td>
              <td class="mono">${{r.hash_hex.slice(0, 16)}}…</td>
              <td class="muted">${{kind}}</td>
            `;
            qs('#receiptsBody').appendChild(tr);
          }}
        }} catch (e) {{
          qs('#receiptsErr').textContent = e.toString();
        }}
      }}

      qs('#refreshBtn').onclick = loadProviders;
      qs('#refreshApprovalsBtn').onclick = loadApprovals;
      qs('#refreshReceiptsBtn').onclick = loadReceipts;

      loadIdentity();
      loadProviders();
      loadApprovals();
      loadReceipts();
    </script>
  </body>
</html>
"#,
        csrf = st.csrf_token
    );
    Html(html)
}

async fn api_identity(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let id = st.client.identity().await.map_err(ApiError::daemon)?;
    Ok(Json(serde_json::json!({ "did": id.did })))
}

async fn api_providers(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let v = st.client.list_providers().await.map_err(ApiError::daemon)?;
    Ok(Json(serde_json::to_value(v).map_err(ApiError::internal)?))
}

async fn api_approvals(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let v = st.client.list_approvals().await.map_err(ApiError::daemon)?;
    Ok(Json(serde_json::to_value(v).map_err(ApiError::internal)?))
}

async fn api_approve(
    State(st): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_csrf(&st, &headers)?;
    let v = st.client.approve(&id).await.map_err(ApiError::daemon)?;
    Ok(Json(serde_json::to_value(v).map_err(ApiError::internal)?))
}

async fn api_receipts(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let v = st.client.list_receipts().await.map_err(ApiError::daemon)?;
    Ok(Json(serde_json::to_value(v).map_err(ApiError::internal)?))
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn internal(e: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: e.to_string(),
        }
    }

    fn daemon(e: briefcase_api::BriefcaseClientError) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            code: "daemon_error",
            message: e.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        error!(code = self.code, msg = %self.message, "api error");
        (
            self.status,
            Json(serde_json::json!({
                "code": self.code,
                "message": self.message,
            })),
        )
            .into_response()
    }
}

fn require_csrf(st: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(tok) = headers.get("x-csrf-token").and_then(|h| h.to_str().ok()) else {
        return Err(ApiError {
            status: StatusCode::UNAUTHORIZED,
            code: "csrf_missing",
            message: "missing x-csrf-token".to_string(),
        });
    };
    if tok != st.csrf_token {
        return Err(ApiError {
            status: StatusCode::UNAUTHORIZED,
            code: "csrf_invalid",
            message: "invalid csrf token".to_string(),
        });
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

fn random_token_b64url(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn ui_host_allowlist_denies_non_loopback_host() -> anyhow::Result<()> {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(enforce_ui_host_allowlist));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("http://example.invalid/")
                    .header(HOST, "evil.example")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn ui_host_allowlist_allows_loopback_hosts() -> anyhow::Result<()> {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(enforce_ui_host_allowlist));

        for h in ["localhost:8787", "127.0.0.1:8787", "[::1]:8787"] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("http://example.invalid/")
                        .header(HOST, h)
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(resp.status(), StatusCode::OK, "host={h}");
        }

        Ok(())
    }
}
