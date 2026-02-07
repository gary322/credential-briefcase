use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context as _;
use briefcase_core::{
    ApprovalKind, ApprovalRequest, ToolEgressPolicy, ToolFilesystemPolicy, ToolLimits,
    ToolManifest, ToolRuntimeKind, util::sha256_hex,
};
use chrono::{DateTime, Datelike as _, Duration, TimeZone as _, Utc};
use rusqlite::{OptionalExtension, params};
use tokio_rusqlite::Connection;
use uuid::Uuid;

#[derive(Clone)]
pub struct Db {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct RemoteMcpServerRecord {
    pub id: String,
    pub endpoint_url: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RemoteMcpOauthRecord {
    pub server_id: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// RFC 7009 token revocation endpoint, if advertised by the auth server.
    pub revocation_endpoint: Option<String>,
    pub resource: String,
    pub dpop_signing_alg_values_supported: Vec<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RemoteMcpOauthClientRecord {
    pub server_id: String,
    pub client_id: String,
    pub scope: String,
}

#[derive(Debug, Clone)]
pub struct OAuthSessionRecord {
    pub state: String,
    pub kind: String,
    pub server_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub scope: String,
    pub token_endpoint: String,
}

#[derive(Debug, Clone)]
pub struct VcUpsert {
    pub vc_jwt: String,
    pub expires_at: DateTime<Utc>,
    pub status_list_url: Option<String>,
    pub status_list_index: Option<i64>,
    pub status_purpose: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct VcRecord {
    pub provider_id: String,
    pub vc_jwt: String,
    pub expires_at: DateTime<Utc>,
    pub status_list_url: Option<String>,
    pub status_list_index: Option<i64>,
    pub status_purpose: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct VcStatusListCacheRecord {
    pub url: String,
    pub encoded_list: String,
    pub status_purpose: String,
    pub status_size: i64,
    pub ttl_ms: Option<i64>,
    pub etag: Option<String>,
    pub fetched_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct PolicyRecord {
    pub policy_text: String,
    pub policy_hash_hex: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct PolicyProposalRecord {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub prompt: String,
    pub base_policy_hash_hex: String,
    pub proposed_policy_text: String,
    pub proposed_policy_hash_hex: String,
    pub diff_json: String,
    pub approval_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct ControlPlaneRecord {
    pub base_url: String,
    pub device_id: Uuid,
    pub policy_signing_pubkey_b64: String,
    pub last_policy_bundle_id: Option<i64>,
    pub last_receipt_upload_id: i64,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl Db {
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create db dir {}", parent.display()))?;
        }

        let conn = Connection::open(path).await?;
        Ok(Self { conn })
    }

    pub async fn init(&self) -> anyhow::Result<()> {
        self.conn
            .call(|conn| {
                conn.pragma_update(None, "journal_mode", "WAL")?;
                conn.pragma_update(None, "synchronous", "NORMAL")?;
                conn.execute_batch(
                    r#"
                    CREATE TABLE IF NOT EXISTS approvals (
                      id                TEXT PRIMARY KEY,
                      created_at_rfc3339 TEXT NOT NULL,
                      expires_at_rfc3339 TEXT NOT NULL,
                      tool_id            TEXT NOT NULL,
                      reason             TEXT NOT NULL,
                      approval_kind      TEXT NOT NULL DEFAULT 'local',
                      summary_json       TEXT NOT NULL,
                      call_hash_hex      TEXT NOT NULL,
                      status             TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS approvals_status_idx ON approvals(status);
                    CREATE INDEX IF NOT EXISTS approvals_expires_idx ON approvals(expires_at_rfc3339);

                    CREATE TABLE IF NOT EXISTS providers (
                      id                TEXT PRIMARY KEY,
                      base_url          TEXT NOT NULL,
                      created_at_rfc3339 TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS budgets (
                      category                TEXT PRIMARY KEY,
                      daily_limit_microusd     INTEGER NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS spend_events (
                      id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                      ts_rfc3339               TEXT NOT NULL,
                      category                 TEXT NOT NULL,
                      amount_microusd          INTEGER NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS spend_events_cat_ts_idx ON spend_events(category, ts_rfc3339);

                    CREATE TABLE IF NOT EXISTS notes (
                      id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                      created_at_rfc3339      TEXT NOT NULL,
                      text                    TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS policy (
                      id                 INTEGER PRIMARY KEY CHECK (id = 1),
                      policy_text        TEXT NOT NULL,
                      policy_hash_hex    TEXT NOT NULL,
                      updated_at_rfc3339 TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS policy_proposals (
                      id                      TEXT PRIMARY KEY,
                      created_at_rfc3339      TEXT NOT NULL,
                      expires_at_rfc3339      TEXT NOT NULL,
                      prompt                  TEXT NOT NULL,
                      base_policy_hash_hex    TEXT NOT NULL,
                      proposed_policy_text    TEXT NOT NULL,
                      proposed_policy_hash_hex TEXT NOT NULL,
                      diff_json               TEXT NOT NULL,
                      approval_id             TEXT
                    );

                    CREATE INDEX IF NOT EXISTS policy_proposals_expires_idx ON policy_proposals(expires_at_rfc3339);

                    CREATE TABLE IF NOT EXISTS identity (
                      id                INTEGER PRIMARY KEY CHECK (id = 1),
                      did               TEXT NOT NULL,
                      created_at_rfc3339 TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS signers (
                      id                TEXT PRIMARY KEY,
                      algorithm         TEXT NOT NULL,
                      pubkey_b64         TEXT NOT NULL,
                      device_name        TEXT,
                      created_at_rfc3339 TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS vcs (
                      provider_id           TEXT PRIMARY KEY,
                      vc_jwt                TEXT NOT NULL,
                      expires_at_rfc3339    TEXT NOT NULL,
                      status_list_url       TEXT,
                      status_list_index     INTEGER,
                      status_purpose        TEXT,
                      revoked_at_rfc3339    TEXT,
                      created_at_rfc3339    TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS vc_status_lists (
                      url                 TEXT PRIMARY KEY,
                      encoded_list        TEXT NOT NULL,
                      status_purpose      TEXT NOT NULL,
                      status_size         INTEGER NOT NULL,
                      ttl_ms              INTEGER,
                      etag                TEXT,
                      fetched_at_rfc3339  TEXT NOT NULL,
                      expires_at_rfc3339  TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS vc_status_lists_expires_idx ON vc_status_lists(expires_at_rfc3339);

                    CREATE TABLE IF NOT EXISTS remote_mcp_servers (
                      id                TEXT PRIMARY KEY,
                      endpoint_url      TEXT NOT NULL,
                      created_at_rfc3339 TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS remote_mcp_oauth (
                      server_id             TEXT PRIMARY KEY,
                      issuer                TEXT NOT NULL,
                      authorization_endpoint TEXT NOT NULL,
                      token_endpoint        TEXT NOT NULL,
                      revocation_endpoint   TEXT,
                      resource              TEXT NOT NULL,
                      dpop_algs_json        TEXT NOT NULL DEFAULT '[]',
                      discovered_at_rfc3339 TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS remote_mcp_oauth_clients (
                      server_id        TEXT PRIMARY KEY,
                      client_id        TEXT NOT NULL,
                      scope            TEXT NOT NULL,
                      updated_at_rfc3339 TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS oauth_sessions (
                      state            TEXT PRIMARY KEY,
                      kind             TEXT NOT NULL,
                      server_id        TEXT NOT NULL,
                      created_at_rfc3339 TEXT NOT NULL,
                      expires_at_rfc3339 TEXT NOT NULL,
                      code_verifier    TEXT NOT NULL,
                      redirect_uri     TEXT NOT NULL,
                      client_id        TEXT NOT NULL,
                      scope            TEXT NOT NULL,
                      token_endpoint   TEXT NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS oauth_sessions_expires_idx ON oauth_sessions(expires_at_rfc3339);
                    CREATE INDEX IF NOT EXISTS oauth_sessions_server_idx ON oauth_sessions(server_id);

                    CREATE TABLE IF NOT EXISTS tool_manifests (
                      tool_id                       TEXT PRIMARY KEY,
                      runtime                       TEXT NOT NULL,
                      allowed_hosts_json            TEXT NOT NULL,
                      allowed_http_path_prefixes_json TEXT NOT NULL,
                      allowed_fs_path_prefixes_json TEXT NOT NULL,
                      max_output_bytes              INTEGER NOT NULL,
                      updated_at_rfc3339            TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS control_plane (
                      id                         INTEGER PRIMARY KEY CHECK (id = 1),
                      base_url                    TEXT NOT NULL,
                      device_id                   TEXT NOT NULL,
                      policy_signing_pubkey_b64   TEXT NOT NULL,
                      last_policy_bundle_id       INTEGER,
                      last_receipt_upload_id      INTEGER NOT NULL DEFAULT 0,
                      last_sync_at_rfc3339        TEXT,
                      last_error                  TEXT,
                      updated_at_rfc3339          TEXT NOT NULL
                    );
                    "#,
                )?;
                Ok(())
            })
            .await?;

        // Best-effort schema migration for older DBs (SQLite has limited ALTER TABLE).
        let _ = self
            .conn
            .call(|conn| {
                let _ = conn.execute(
                    "ALTER TABLE remote_mcp_oauth ADD COLUMN dpop_algs_json TEXT NOT NULL DEFAULT '[]'",
                    [],
                );
                let _ = conn.execute(
                    "ALTER TABLE remote_mcp_oauth ADD COLUMN revocation_endpoint TEXT",
                    [],
                );
                let _ = conn.execute("ALTER TABLE vcs ADD COLUMN status_list_url TEXT", []);
                let _ = conn.execute("ALTER TABLE vcs ADD COLUMN status_list_index INTEGER", []);
                let _ = conn.execute("ALTER TABLE vcs ADD COLUMN status_purpose TEXT", []);
                let _ = conn.execute("ALTER TABLE vcs ADD COLUMN revoked_at_rfc3339 TEXT", []);
                let _ = conn.execute(
                    "ALTER TABLE approvals ADD COLUMN approval_kind TEXT NOT NULL DEFAULT 'local'",
                    [],
                );
                let _ = conn.execute(
                    "ALTER TABLE signers ADD COLUMN algorithm TEXT NOT NULL DEFAULT 'ed25519'",
                    [],
                );
                let _ = conn.execute("ALTER TABLE signers ADD COLUMN device_name TEXT", []);
                Ok(())
            })
            .await;

        // Seed a conservative default budget if missing.
        // $3/day for read tools, $0/day for write/admin (forcing approval).
        self.set_budget_default("read", 3_000_000).await?;
        self.set_budget_default("write", 0).await?;
        self.set_budget_default("admin", 0).await?;

        Ok(())
    }

    async fn set_budget_default(
        &self,
        category: &str,
        daily_limit_microusd: i64,
    ) -> anyhow::Result<()> {
        let category = category.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO budgets(category, daily_limit_microusd) VALUES (?1, ?2)",
                    params![category, daily_limit_microusd],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn set_budget(
        &self,
        category: &str,
        daily_limit_microusd: i64,
    ) -> anyhow::Result<()> {
        let category = category.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO budgets(category, daily_limit_microusd) VALUES (?1, ?2)
                    ON CONFLICT(category) DO UPDATE SET daily_limit_microusd=excluded.daily_limit_microusd
                    "#,
                    params![category, daily_limit_microusd],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn list_budgets(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT category, daily_limit_microusd FROM budgets ORDER BY category ASC",
                )?;
                let rows = stmt.query_map([], |row| {
                    let category: String = row.get(0)?;
                    let daily: i64 = row.get(1)?;
                    Ok((category, daily))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await?;
        Ok(rows)
    }

    pub async fn upsert_remote_mcp_server(
        &self,
        id: &str,
        endpoint_url: &str,
    ) -> anyhow::Result<()> {
        let id = id.to_string();
        let endpoint_url = endpoint_url.to_string();
        let created_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO remote_mcp_servers(id, endpoint_url, created_at_rfc3339)
                    VALUES (?1, ?2, ?3)
                    ON CONFLICT(id) DO UPDATE SET endpoint_url=excluded.endpoint_url
                    "#,
                    params![id, endpoint_url, created_at],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn delete_remote_mcp_server(&self, id: &str) -> anyhow::Result<()> {
        let id = id.to_string();
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM remote_mcp_servers WHERE id=?1", params![id])?;
                conn.execute(
                    "DELETE FROM remote_mcp_oauth WHERE server_id=?1",
                    params![id],
                )?;
                conn.execute(
                    "DELETE FROM remote_mcp_oauth_clients WHERE server_id=?1",
                    params![id],
                )?;
                conn.execute("DELETE FROM oauth_sessions WHERE server_id=?1", params![id])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn list_remote_mcp_servers(&self) -> anyhow::Result<Vec<RemoteMcpServerRecord>> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt = conn
                    .prepare("SELECT id, endpoint_url FROM remote_mcp_servers ORDER BY id ASC")?;
                let rows = stmt.query_map([], |row| {
                    Ok(RemoteMcpServerRecord {
                        id: row.get::<_, String>(0)?,
                        endpoint_url: row.get::<_, String>(1)?,
                    })
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await?;
        Ok(rows)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_remote_mcp_oauth(
        &self,
        server_id: &str,
        issuer: &str,
        authorization_endpoint: &str,
        token_endpoint: &str,
        revocation_endpoint: Option<&str>,
        resource: &str,
        dpop_signing_alg_values_supported: &[String],
    ) -> anyhow::Result<()> {
        let server_id = server_id.to_string();
        let issuer = issuer.to_string();
        let authorization_endpoint = authorization_endpoint.to_string();
        let token_endpoint = token_endpoint.to_string();
        let revocation_endpoint = revocation_endpoint.map(|s| s.to_string());
        let resource = resource.to_string();
        let dpop_algs_json = serde_json::to_string(dpop_signing_alg_values_supported)
            .context("serialize dpop algs")?;
        let discovered_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO remote_mcp_oauth(server_id, issuer, authorization_endpoint, token_endpoint, revocation_endpoint, resource, dpop_algs_json, discovered_at_rfc3339)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    ON CONFLICT(server_id) DO UPDATE SET
                      issuer=excluded.issuer,
                      authorization_endpoint=excluded.authorization_endpoint,
                      token_endpoint=excluded.token_endpoint,
                      revocation_endpoint=excluded.revocation_endpoint,
                      resource=excluded.resource,
                      dpop_algs_json=excluded.dpop_algs_json,
                      discovered_at_rfc3339=excluded.discovered_at_rfc3339
                    "#,
                    params![
                        server_id,
                        issuer,
                        authorization_endpoint,
                        token_endpoint,
                        revocation_endpoint,
                        resource,
                        dpop_algs_json,
                        discovered_at,
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn get_remote_mcp_oauth(
        &self,
        server_id: &str,
    ) -> anyhow::Result<Option<RemoteMcpOauthRecord>> {
        let server_id = server_id.to_string();
        let row = self
            .conn
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        r#"
                        SELECT server_id, issuer, authorization_endpoint, token_endpoint, revocation_endpoint, resource, dpop_algs_json
                        FROM remote_mcp_oauth
                        WHERE server_id=?1
                        "#,
                        params![server_id],
                        |row| {
                            let dpop_algs_json: String = row.get(6)?;
                            let dpop_signing_alg_values_supported: Vec<String> =
                                serde_json::from_str(&dpop_algs_json).unwrap_or_default();
                            Ok(RemoteMcpOauthRecord {
                                server_id: row.get(0)?,
                                issuer: row.get(1)?,
                                authorization_endpoint: row.get(2)?,
                                token_endpoint: row.get(3)?,
                                revocation_endpoint: row.get(4)?,
                                resource: row.get(5)?,
                                dpop_signing_alg_values_supported,
                            })
                        },
                    )
                    .optional()?)
            })
            .await?;
        Ok(row)
    }

    pub async fn upsert_remote_mcp_oauth_client(
        &self,
        server_id: &str,
        client_id: &str,
        scope: &str,
    ) -> anyhow::Result<()> {
        let server_id = server_id.to_string();
        let client_id = client_id.to_string();
        let scope = scope.to_string();
        let updated_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO remote_mcp_oauth_clients(server_id, client_id, scope, updated_at_rfc3339)
                    VALUES (?1, ?2, ?3, ?4)
                    ON CONFLICT(server_id) DO UPDATE SET
                      client_id=excluded.client_id,
                      scope=excluded.scope,
                      updated_at_rfc3339=excluded.updated_at_rfc3339
                    "#,
                    params![server_id, client_id, scope, updated_at],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn get_remote_mcp_oauth_client(
        &self,
        server_id: &str,
    ) -> anyhow::Result<Option<RemoteMcpOauthClientRecord>> {
        let server_id = server_id.to_string();
        let row = self
            .conn
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        r#"
                        SELECT server_id, client_id, scope
                        FROM remote_mcp_oauth_clients
                        WHERE server_id=?1
                        "#,
                        params![server_id],
                        |row| {
                            Ok(RemoteMcpOauthClientRecord {
                                server_id: row.get(0)?,
                                client_id: row.get(1)?,
                                scope: row.get(2)?,
                            })
                        },
                    )
                    .optional()?)
            })
            .await?;
        Ok(row)
    }

    pub async fn create_oauth_session(&self, session: OAuthSessionRecord) -> anyhow::Result<()> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO oauth_sessions(
                      state, kind, server_id, created_at_rfc3339, expires_at_rfc3339,
                      code_verifier, redirect_uri, client_id, scope, token_endpoint
                    )
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                    "#,
                    params![
                        session.state,
                        session.kind,
                        session.server_id,
                        session.created_at.to_rfc3339(),
                        session.expires_at.to_rfc3339(),
                        session.code_verifier,
                        session.redirect_uri,
                        session.client_id,
                        session.scope,
                        session.token_endpoint
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn get_oauth_session(
        &self,
        state: &str,
    ) -> anyhow::Result<Option<OAuthSessionRecord>> {
        let state = state.to_string();
        let row = self
            .conn
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        r#"
                        SELECT
                          state, kind, server_id, created_at_rfc3339, expires_at_rfc3339,
                          code_verifier, redirect_uri, client_id, scope, token_endpoint
                        FROM oauth_sessions
                        WHERE state=?1
                        "#,
                        params![state],
                        |row| {
                            let created_at: String = row.get(3)?;
                            let expires_at: String = row.get(4)?;
                            Ok(OAuthSessionRecord {
                                state: row.get(0)?,
                                kind: row.get(1)?,
                                server_id: row.get(2)?,
                                created_at: DateTime::parse_from_rfc3339(&created_at)
                                    .map_err(|e| {
                                        rusqlite::Error::FromSqlConversionFailure(
                                            0,
                                            rusqlite::types::Type::Text,
                                            Box::new(e),
                                        )
                                    })?
                                    .with_timezone(&Utc),
                                expires_at: DateTime::parse_from_rfc3339(&expires_at)
                                    .map_err(|e| {
                                        rusqlite::Error::FromSqlConversionFailure(
                                            0,
                                            rusqlite::types::Type::Text,
                                            Box::new(e),
                                        )
                                    })?
                                    .with_timezone(&Utc),
                                code_verifier: row.get(5)?,
                                redirect_uri: row.get(6)?,
                                client_id: row.get(7)?,
                                scope: row.get(8)?,
                                token_endpoint: row.get(9)?,
                            })
                        },
                    )
                    .optional()?)
            })
            .await?;
        Ok(row)
    }

    pub async fn delete_oauth_session(&self, state: &str) -> anyhow::Result<()> {
        let state = state.to_string();
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM oauth_sessions WHERE state=?1", params![state])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn budget_allows(
        &self,
        category: &str,
        amount_microusd: i64,
    ) -> anyhow::Result<bool> {
        let category = category.to_string();
        let res = self.conn
            .call(move |conn| {
                let daily_limit: i64 = conn
                    .query_row(
                        "SELECT daily_limit_microusd FROM budgets WHERE category=?1",
                        params![category],
                        |row| row.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);

                let now = Utc::now();
                let day_start = Utc
                    .with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
                    .single()
                    .unwrap_or(now);
                let day_end = day_start + Duration::days(1);

                let spent: i64 = conn.query_row(
                    "SELECT COALESCE(SUM(amount_microusd), 0) FROM spend_events WHERE category=?1 AND ts_rfc3339 >= ?2 AND ts_rfc3339 < ?3",
                    params![category, day_start.to_rfc3339(), day_end.to_rfc3339()],
                    |row| row.get(0),
                )?;

                Ok(spent.saturating_add(amount_microusd) <= daily_limit)
            })
            .await?;

        Ok(res)
    }

    pub async fn record_spend(&self, category: &str, amount_microusd: i64) -> anyhow::Result<()> {
        let category = category.to_string();
        let ts = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO spend_events(ts_rfc3339, category, amount_microusd) VALUES (?1, ?2, ?3)",
                    params![ts, category, amount_microusd],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn add_note(&self, text: &str) -> anyhow::Result<i64> {
        let text = text.to_string();
        let created_at = Utc::now().to_rfc3339();
        let id = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO notes(created_at_rfc3339, text) VALUES (?1, ?2)",
                    params![created_at, text],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    pub async fn upsert_provider(&self, id: &str, base_url: &str) -> anyhow::Result<()> {
        let id = id.to_string();
        let base_url = base_url.to_string();
        let created_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO providers(id, base_url, created_at_rfc3339)
                    VALUES (?1, ?2, ?3)
                    ON CONFLICT(id) DO UPDATE SET base_url=excluded.base_url
                    "#,
                    params![id, base_url, created_at],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn list_providers(&self) -> anyhow::Result<Vec<(String, String)>> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt =
                    conn.prepare("SELECT id, base_url FROM providers ORDER BY id ASC")?;
                let rows = stmt.query_map([], |row| {
                    let id: String = row.get(0)?;
                    let base_url: String = row.get(1)?;
                    Ok((id, base_url))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await?;
        Ok(rows)
    }

    pub async fn provider_base_url(&self, id: &str) -> anyhow::Result<Option<String>> {
        let id = id.to_string();
        let row = self
            .conn
            .call(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT base_url FROM providers WHERE id=?1",
                        params![id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                Ok(row)
            })
            .await?;
        Ok(row)
    }

    pub async fn delete_provider(&self, id: &str) -> anyhow::Result<()> {
        let id = id.to_string();
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM providers WHERE id=?1", params![id])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn delete_vc(&self, provider_id: &str) -> anyhow::Result<()> {
        let provider_id = provider_id.to_string();
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM vcs WHERE provider_id=?1", params![provider_id])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn identity_did(&self) -> anyhow::Result<Option<String>> {
        let did = self
            .conn
            .call(|conn| {
                let did = conn
                    .query_row("SELECT did FROM identity WHERE id=1", [], |row| {
                        row.get::<_, String>(0)
                    })
                    .optional()?;
                Ok(did)
            })
            .await?;
        Ok(did)
    }

    pub async fn set_identity_did(&self, did: &str) -> anyhow::Result<()> {
        let did = did.to_string();
        let created_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO identity(id, did, created_at_rfc3339)
                    VALUES (1, ?1, ?2)
                    ON CONFLICT(id) DO UPDATE SET did=excluded.did
                    "#,
                    params![did, created_at],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn upsert_signer(
        &self,
        signer_id: Uuid,
        algorithm: &str,
        pubkey_b64: &str,
        device_name: Option<&str>,
    ) -> anyhow::Result<()> {
        let signer_id = signer_id.to_string();
        let algorithm = algorithm.to_string();
        let pubkey_b64 = pubkey_b64.to_string();
        let device_name = device_name.map(|s| s.to_string());
        let created_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO signers(id, algorithm, pubkey_b64, device_name, created_at_rfc3339)
                    VALUES (?1, ?2, ?3, ?4, ?5)
                    ON CONFLICT(id) DO UPDATE SET algorithm=excluded.algorithm, pubkey_b64=excluded.pubkey_b64, device_name=excluded.device_name
                    "#,
                    params![signer_id, algorithm, pubkey_b64, device_name, created_at],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn signer_pubkey_b64(
        &self,
        signer_id: Uuid,
    ) -> anyhow::Result<Option<(String, String)>> {
        let signer_id = signer_id.to_string();
        let row = self
            .conn
            .call(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT algorithm, pubkey_b64 FROM signers WHERE id=?1",
                        params![signer_id],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                    )
                    .optional()?;
                Ok(row)
            })
            .await?;
        Ok(row)
    }

    pub async fn has_any_signers(&self) -> anyhow::Result<bool> {
        let n: i64 = self
            .conn
            .call(|conn| {
                let n: i64 = conn.query_row("SELECT COUNT(*) FROM signers", [], |r| r.get(0))?;
                Ok(n)
            })
            .await?;
        Ok(n > 0)
    }

    pub async fn upsert_vc(&self, provider_id: &str, vc: VcUpsert) -> anyhow::Result<()> {
        let provider_id = provider_id.to_string();
        let vc_jwt = vc.vc_jwt;
        let expires_at_rfc3339 = vc.expires_at.to_rfc3339();
        let status_list_url = vc.status_list_url;
        let status_list_index = vc.status_list_index;
        let status_purpose = vc.status_purpose;
        let created_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO vcs(provider_id, vc_jwt, expires_at_rfc3339, status_list_url, status_list_index, status_purpose, revoked_at_rfc3339, created_at_rfc3339)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)
                    ON CONFLICT(provider_id) DO UPDATE SET
                      vc_jwt=excluded.vc_jwt,
                      expires_at_rfc3339=excluded.expires_at_rfc3339,
                      status_list_url=excluded.status_list_url,
                      status_list_index=excluded.status_list_index,
                      status_purpose=excluded.status_purpose,
                      revoked_at_rfc3339=NULL
                    "#,
                    params![
                        provider_id,
                        vc_jwt,
                        expires_at_rfc3339,
                        status_list_url,
                        status_list_index,
                        status_purpose,
                        created_at
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn get_vc(
        &self,
        provider_id: &str,
    ) -> anyhow::Result<Option<(String, DateTime<Utc>)>> {
        let provider_id = provider_id.to_string();
        let row = self
            .conn
            .call(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT vc_jwt, expires_at_rfc3339 FROM vcs WHERE provider_id=?1 AND revoked_at_rfc3339 IS NULL",
                        params![provider_id],
                        |row| {
                            let vc_jwt: String = row.get(0)?;
                            let expires_at: String = row.get(1)?;
                            Ok((vc_jwt, expires_at))
                        },
                    )
                    .optional()?;
                Ok(row)
            })
            .await?;

        match row {
            Some((vc_jwt, expires_at_rfc3339)) => {
                let expires_at = DateTime::parse_from_rfc3339(&expires_at_rfc3339)
                    .with_context(|| "parse vc expiry")?
                    .with_timezone(&Utc);
                Ok(Some((vc_jwt, expires_at)))
            }
            None => Ok(None),
        }
    }

    pub async fn vc_record(&self, provider_id: &str) -> anyhow::Result<Option<VcRecord>> {
        let provider_id = provider_id.to_string();
        let row = self
            .conn
            .call(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT provider_id, vc_jwt, expires_at_rfc3339, status_list_url, status_list_index, status_purpose, revoked_at_rfc3339 FROM vcs WHERE provider_id=?1",
                        params![provider_id],
                        |row| {
                            let provider_id: String = row.get(0)?;
                            let vc_jwt: String = row.get(1)?;
                            let expires_at: String = row.get(2)?;
                            let status_list_url: Option<String> = row.get(3)?;
                            let status_list_index: Option<i64> = row.get(4)?;
                            let status_purpose: Option<String> = row.get(5)?;
                            let revoked_at: Option<String> = row.get(6)?;
                            Ok((
                                provider_id,
                                vc_jwt,
                                expires_at,
                                status_list_url,
                                status_list_index,
                                status_purpose,
                                revoked_at,
                            ))
                        },
                    )
                    .optional()?;
                Ok(row)
            })
            .await?;

        let Some((
            provider_id,
            vc_jwt,
            expires_at_rfc3339,
            status_list_url,
            status_list_index,
            status_purpose,
            revoked_at_rfc3339,
        )) = row
        else {
            return Ok(None);
        };

        let expires_at = DateTime::parse_from_rfc3339(&expires_at_rfc3339)
            .with_context(|| "parse vc expiry")?
            .with_timezone(&Utc);
        let revoked_at = match revoked_at_rfc3339 {
            Some(s) => Some(
                DateTime::parse_from_rfc3339(&s)
                    .with_context(|| "parse vc revoked_at")?
                    .with_timezone(&Utc),
            ),
            None => None,
        };

        Ok(Some(VcRecord {
            provider_id,
            vc_jwt,
            expires_at,
            status_list_url,
            status_list_index,
            status_purpose,
            revoked_at,
        }))
    }

    pub async fn mark_vc_revoked(
        &self,
        provider_id: &str,
        revoked_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let provider_id = provider_id.to_string();
        let revoked_at_rfc3339 = revoked_at.to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE vcs SET revoked_at_rfc3339=?2 WHERE provider_id=?1",
                    params![provider_id, revoked_at_rfc3339],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn get_vc_status_list_cache(
        &self,
        url: &str,
    ) -> anyhow::Result<Option<VcStatusListCacheRecord>> {
        let url = url.to_string();
        let row = self
            .conn
            .call(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT url, encoded_list, status_purpose, status_size, ttl_ms, etag, fetched_at_rfc3339, expires_at_rfc3339 FROM vc_status_lists WHERE url=?1",
                        params![url],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, Option<i64>>(4)?,
                                row.get::<_, Option<String>>(5)?,
                                row.get::<_, String>(6)?,
                                row.get::<_, String>(7)?,
                            ))
                        },
                    )
                    .optional()?;
                Ok(row)
            })
            .await?;

        let Some((
            url,
            encoded_list,
            status_purpose,
            status_size,
            ttl_ms,
            etag,
            fetched_at_rfc3339,
            expires_at_rfc3339,
        )) = row
        else {
            return Ok(None);
        };

        let fetched_at = DateTime::parse_from_rfc3339(&fetched_at_rfc3339)
            .with_context(|| "parse status list fetched_at")?
            .with_timezone(&Utc);
        let expires_at = DateTime::parse_from_rfc3339(&expires_at_rfc3339)
            .with_context(|| "parse status list expires_at")?
            .with_timezone(&Utc);

        Ok(Some(VcStatusListCacheRecord {
            url,
            encoded_list,
            status_purpose,
            status_size,
            ttl_ms,
            etag,
            fetched_at,
            expires_at,
        }))
    }

    pub async fn upsert_vc_status_list_cache(
        &self,
        rec: VcStatusListCacheRecord,
    ) -> anyhow::Result<()> {
        let url = rec.url;
        let encoded_list = rec.encoded_list;
        let status_purpose = rec.status_purpose;
        let status_size = rec.status_size;
        let ttl_ms = rec.ttl_ms;
        let etag = rec.etag;
        let fetched_at_rfc3339 = rec.fetched_at.to_rfc3339();
        let expires_at_rfc3339 = rec.expires_at.to_rfc3339();

        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO vc_status_lists(url, encoded_list, status_purpose, status_size, ttl_ms, etag, fetched_at_rfc3339, expires_at_rfc3339)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    ON CONFLICT(url) DO UPDATE SET
                      encoded_list=excluded.encoded_list,
                      status_purpose=excluded.status_purpose,
                      status_size=excluded.status_size,
                      ttl_ms=excluded.ttl_ms,
                      etag=excluded.etag,
                      fetched_at_rfc3339=excluded.fetched_at_rfc3339,
                      expires_at_rfc3339=excluded.expires_at_rfc3339
                    "#,
                    params![
                        url,
                        encoded_list,
                        status_purpose,
                        status_size,
                        ttl_ms,
                        etag,
                        fetched_at_rfc3339,
                        expires_at_rfc3339
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn list_note_ids(&self, limit: usize) -> anyhow::Result<Vec<i64>> {
        let limit = limit.min(200) as i64;
        let ids = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT id FROM notes ORDER BY id DESC LIMIT ?1")?;
                let rows = stmt.query_map(params![limit], |row| row.get::<_, i64>(0))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await?;
        Ok(ids)
    }

    pub async fn policy(&self) -> anyhow::Result<Option<PolicyRecord>> {
        self.conn
            .call(|conn| {
                let row: Option<(String, String, String)> = conn
                    .query_row(
                        "SELECT policy_text, policy_hash_hex, updated_at_rfc3339 FROM policy WHERE id=1",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                let Some((policy_text, policy_hash_hex, updated_at_rfc3339)) = row else {
                    return Ok(None);
                };
                let updated_at = updated_at_rfc3339.parse::<DateTime<Utc>>().map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(Some(PolicyRecord {
                    policy_text,
                    policy_hash_hex,
                    updated_at,
                }))
            })
            .await
            .map_err(Into::into)
    }

    pub async fn upsert_policy(&self, policy_text: &str) -> anyhow::Result<PolicyRecord> {
        let policy_text = policy_text.to_string();
        let policy_hash_hex = sha256_hex(policy_text.as_bytes());
        let updated_at = Utc::now().to_rfc3339();

        let policy_text_db = policy_text.clone();
        let policy_hash_hex_db = policy_hash_hex.clone();
        let updated_at_db = updated_at.clone();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO policy(id, policy_text, policy_hash_hex, updated_at_rfc3339)
                    VALUES (1, ?1, ?2, ?3)
                    ON CONFLICT(id) DO UPDATE SET
                      policy_text=excluded.policy_text,
                      policy_hash_hex=excluded.policy_hash_hex,
                      updated_at_rfc3339=excluded.updated_at_rfc3339
                    "#,
                    params![policy_text_db, policy_hash_hex_db, updated_at_db],
                )?;
                Ok(())
            })
            .await?;

        Ok(PolicyRecord {
            policy_text,
            policy_hash_hex,
            updated_at: updated_at.parse::<DateTime<Utc>>()?,
        })
    }

    pub async fn ensure_policy(&self, default_policy_text: &str) -> anyhow::Result<PolicyRecord> {
        if let Some(p) = self.policy().await? {
            return Ok(p);
        }
        self.upsert_policy(default_policy_text).await
    }

    pub async fn control_plane(&self) -> anyhow::Result<Option<ControlPlaneRecord>> {
        self.conn
            .call(|conn| {
                #[derive(Debug)]
                struct ControlPlaneRow {
                    base_url: String,
                    device_id: String,
                    policy_signing_pubkey_b64: String,
                    last_policy_bundle_id: Option<i64>,
                    last_receipt_upload_id: i64,
                    last_sync_at_rfc3339: Option<String>,
                    last_error: Option<String>,
                    updated_at_rfc3339: String,
                }

                let row: Option<ControlPlaneRow> = conn
                    .query_row(
                        r#"
                        SELECT
                          base_url,
                          device_id,
                          policy_signing_pubkey_b64,
                          last_policy_bundle_id,
                          last_receipt_upload_id,
                          last_sync_at_rfc3339,
                          last_error,
                          updated_at_rfc3339
                        FROM control_plane
                        WHERE id=1
                        "#,
                        [],
                        |r| {
                            Ok(ControlPlaneRow {
                                base_url: r.get(0)?,
                                device_id: r.get(1)?,
                                policy_signing_pubkey_b64: r.get(2)?,
                                last_policy_bundle_id: r.get(3)?,
                                last_receipt_upload_id: r.get(4)?,
                                last_sync_at_rfc3339: r.get(5)?,
                                last_error: r.get(6)?,
                                updated_at_rfc3339: r.get(7)?,
                            })
                        },
                    )
                    .optional()?;

                let Some(row) = row else {
                    return Ok(None);
                };

                let device_id = Uuid::parse_str(&row.device_id).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;

                let last_sync_at = match row.last_sync_at_rfc3339 {
                    Some(s) => Some(s.parse::<DateTime<Utc>>().map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?),
                    None => None,
                };

                let updated_at = row
                    .updated_at_rfc3339
                    .parse::<DateTime<Utc>>()
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;

                Ok(Some(ControlPlaneRecord {
                    base_url: row.base_url,
                    device_id,
                    policy_signing_pubkey_b64: row.policy_signing_pubkey_b64,
                    last_policy_bundle_id: row.last_policy_bundle_id,
                    last_receipt_upload_id: row.last_receipt_upload_id,
                    last_sync_at,
                    last_error: row.last_error,
                    updated_at,
                }))
            })
            .await
            .map_err(Into::into)
    }

    pub async fn upsert_control_plane_enrollment(
        &self,
        base_url: &str,
        device_id: Uuid,
        policy_signing_pubkey_b64: &str,
        last_policy_bundle_id: Option<i64>,
    ) -> anyhow::Result<()> {
        let base_url = base_url.to_string();
        let device_id = device_id.to_string();
        let policy_signing_pubkey_b64 = policy_signing_pubkey_b64.to_string();
        let updated_at = Utc::now().to_rfc3339();

        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO control_plane(
                      id,
                      base_url,
                      device_id,
                      policy_signing_pubkey_b64,
                      last_policy_bundle_id,
                      last_receipt_upload_id,
                      last_sync_at_rfc3339,
                      last_error,
                      updated_at_rfc3339
                    ) VALUES (1, ?1, ?2, ?3, ?4, 0, NULL, NULL, ?5)
                    ON CONFLICT(id) DO UPDATE SET
                      base_url=excluded.base_url,
                      device_id=excluded.device_id,
                      policy_signing_pubkey_b64=excluded.policy_signing_pubkey_b64,
                      last_policy_bundle_id=excluded.last_policy_bundle_id,
                      last_receipt_upload_id=0,
                      last_sync_at_rfc3339=NULL,
                      last_error=NULL,
                      updated_at_rfc3339=excluded.updated_at_rfc3339
                    "#,
                    params![
                        base_url,
                        device_id,
                        policy_signing_pubkey_b64,
                        last_policy_bundle_id,
                        updated_at,
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn delete_control_plane_enrollment(&self) -> anyhow::Result<()> {
        self.conn
            .call(|conn| {
                conn.execute("DELETE FROM control_plane WHERE id=1", [])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn update_control_plane_sync_status(
        &self,
        last_sync_at: DateTime<Utc>,
        last_error: Option<&str>,
    ) -> anyhow::Result<()> {
        let last_sync_at = last_sync_at.to_rfc3339();
        let last_error = last_error.map(|s| s.to_string());
        let updated_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE control_plane SET last_sync_at_rfc3339=?1, last_error=?2, updated_at_rfc3339=?3 WHERE id=1",
                    params![last_sync_at, last_error, updated_at],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn set_control_plane_last_policy_bundle_id(
        &self,
        bundle_id: i64,
    ) -> anyhow::Result<()> {
        let updated_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE control_plane SET last_policy_bundle_id=?1, updated_at_rfc3339=?2 WHERE id=1",
                    params![bundle_id, updated_at],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn set_control_plane_last_receipt_upload_id(
        &self,
        receipt_id: i64,
    ) -> anyhow::Result<()> {
        let updated_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE control_plane SET last_receipt_upload_id=?1, updated_at_rfc3339=?2 WHERE id=1",
                    params![receipt_id, updated_at],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn apply_policy_and_budgets(
        &self,
        policy_text: &str,
        budgets: &BTreeMap<String, i64>,
    ) -> anyhow::Result<PolicyRecord> {
        let policy_text = policy_text.to_string();
        let policy_hash_hex = sha256_hex(policy_text.as_bytes());
        let updated_at = Utc::now();

        let policy_text_db = policy_text.clone();
        let policy_hash_hex_db = policy_hash_hex.clone();
        let updated_at_db = updated_at.to_rfc3339();
        let budgets_db = budgets.clone();

        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;

                tx.execute(
                    r#"
                    INSERT INTO policy(id, policy_text, policy_hash_hex, updated_at_rfc3339)
                    VALUES (1, ?1, ?2, ?3)
                    ON CONFLICT(id) DO UPDATE SET
                      policy_text=excluded.policy_text,
                      policy_hash_hex=excluded.policy_hash_hex,
                      updated_at_rfc3339=excluded.updated_at_rfc3339
                    "#,
                    params![policy_text_db, policy_hash_hex_db, updated_at_db],
                )?;

                for (cat, limit) in budgets_db {
                    if limit < 0 {
                        continue;
                    }
                    tx.execute(
                        r#"
                        INSERT INTO budgets(category, daily_limit_microusd)
                        VALUES (?1, ?2)
                        ON CONFLICT(category) DO UPDATE SET
                          daily_limit_microusd=excluded.daily_limit_microusd
                        "#,
                        params![cat, limit],
                    )?;
                }

                tx.commit()?;
                Ok(())
            })
            .await?;

        Ok(PolicyRecord {
            policy_text,
            policy_hash_hex,
            updated_at,
        })
    }

    pub async fn create_policy_proposal(
        &self,
        prompt: &str,
        base_policy_hash_hex: &str,
        proposed_policy_text: &str,
        proposed_policy_hash_hex: &str,
        diff_json: &str,
    ) -> anyhow::Result<PolicyProposalRecord> {
        let id = Uuid::new_v4();
        let created_at = Utc::now();
        let expires_at = created_at + Duration::minutes(10);

        let prompt = prompt.to_string();
        let base_policy_hash_hex = base_policy_hash_hex.to_string();
        let proposed_policy_text = proposed_policy_text.to_string();
        let proposed_policy_hash_hex = proposed_policy_hash_hex.to_string();
        let diff_json = diff_json.to_string();
        let created_at_rfc3339 = created_at.to_rfc3339();
        let expires_at_rfc3339 = expires_at.to_rfc3339();

        let prompt_db = prompt.clone();
        let base_policy_hash_hex_db = base_policy_hash_hex.clone();
        let proposed_policy_text_db = proposed_policy_text.clone();
        let proposed_policy_hash_hex_db = proposed_policy_hash_hex.clone();
        let diff_json_db = diff_json.clone();
        let created_at_rfc3339_db = created_at_rfc3339.clone();
        let expires_at_rfc3339_db = expires_at_rfc3339.clone();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO policy_proposals(
                      id,
                      created_at_rfc3339,
                      expires_at_rfc3339,
                      prompt,
                      base_policy_hash_hex,
                      proposed_policy_text,
                      proposed_policy_hash_hex,
                      diff_json,
                      approval_id
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)
                    "#,
                    params![
                        id.to_string(),
                        created_at_rfc3339_db,
                        expires_at_rfc3339_db,
                        prompt_db,
                        base_policy_hash_hex_db,
                        proposed_policy_text_db,
                        proposed_policy_hash_hex_db,
                        diff_json_db,
                    ],
                )?;
                Ok(())
            })
            .await?;

        Ok(PolicyProposalRecord {
            id,
            created_at,
            expires_at,
            prompt,
            base_policy_hash_hex,
            proposed_policy_text,
            proposed_policy_hash_hex,
            diff_json,
            approval_id: None,
        })
    }

    pub async fn policy_proposal(&self, id: Uuid) -> anyhow::Result<Option<PolicyProposalRecord>> {
        let id_s = id.to_string();
        self.conn
            .call(move |conn| {
                // Expire proposals opportunistically.
                let now = Utc::now().to_rfc3339();
                conn.execute(
                    "DELETE FROM policy_proposals WHERE expires_at_rfc3339 < ?1",
                    params![now],
                )?;

                let row: Option<PolicyProposalRecord> = conn
                    .query_row(
                        r#"
                        SELECT id, created_at_rfc3339, expires_at_rfc3339, prompt, base_policy_hash_hex,
                               proposed_policy_text, proposed_policy_hash_hex, diff_json, approval_id
                        FROM policy_proposals WHERE id=?1
                        "#,
                        params![id_s],
                        |r| {
                            let id_s: String = r.get(0)?;
                            let created_at_s: String = r.get(1)?;
                            let expires_at_s: String = r.get(2)?;
                            let prompt: String = r.get(3)?;
                            let base_hash: String = r.get(4)?;
                            let proposed_text: String = r.get(5)?;
                            let proposed_hash: String = r.get(6)?;
                            let diff_json: String = r.get(7)?;
                            let approval_id_s: Option<String> = r.get(8)?;

                            let created_at = created_at_s.parse::<DateTime<Utc>>().map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    1,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                )
                            })?;
                            let expires_at = expires_at_s.parse::<DateTime<Utc>>().map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    2,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                )
                            })?;

                            let id = Uuid::parse_str(&id_s).map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    0,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                )
                            })?;
                            let approval_id = match approval_id_s {
                                Some(s) => Some(Uuid::parse_str(&s).map_err(|e| {
                                    rusqlite::Error::FromSqlConversionFailure(
                                        8,
                                        rusqlite::types::Type::Text,
                                        Box::new(e),
                                    )
                                })?),
                                None => None,
                            };

                            Ok(PolicyProposalRecord {
                                id,
                                created_at,
                                expires_at,
                                prompt,
                                base_policy_hash_hex: base_hash,
                                proposed_policy_text: proposed_text,
                                proposed_policy_hash_hex: proposed_hash,
                                diff_json,
                                approval_id,
                            })
                        },
                    )
                    .optional()?;
                Ok(row)
            })
            .await
            .map_err(Into::into)
    }

    pub async fn set_policy_proposal_approval_id(
        &self,
        proposal_id: Uuid,
        approval_id: Uuid,
    ) -> anyhow::Result<()> {
        let proposal_id_s = proposal_id.to_string();
        let approval_id_s = approval_id.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE policy_proposals SET approval_id=?1 WHERE id=?2",
                    params![approval_id_s, proposal_id_s],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn delete_policy_proposal(&self, id: Uuid) -> anyhow::Result<()> {
        let id_s = id.to_string();
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM policy_proposals WHERE id=?1", params![id_s])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn create_approval_with_summary(
        &self,
        tool_id: &str,
        reason: &str,
        kind: ApprovalKind,
        args: &serde_json::Value,
        summary_override: Option<serde_json::Value>,
    ) -> anyhow::Result<ApprovalRequest> {
        let id = Uuid::new_v4();
        let created_at = Utc::now();
        let expires_at = created_at + Duration::minutes(10);

        let tool_id_s = tool_id.to_string();
        let reason_s = reason.to_string();
        let kind_s = match kind {
            ApprovalKind::Local => "local",
            ApprovalKind::MobileSigner => "mobile_signer",
        }
        .to_string();
        let args_hash = sha256_hex(serde_json::to_vec(args)?.as_slice());
        let kind_s_for_summary = kind_s.clone();
        let summary = summary_override.unwrap_or_else(|| {
            serde_json::json!({
                "tool_id": tool_id,
                "reason": reason,
                "kind": kind_s_for_summary,
                "args_hash": args_hash,
            })
        });
        let summary_json = serde_json::to_string(&summary)?;
        let call_hash_hex = sha256_hex(
            serde_json::to_vec(&serde_json::json!({"tool_id": tool_id, "args": args}))?.as_slice(),
        );

        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO approvals(id, created_at_rfc3339, expires_at_rfc3339, tool_id, reason, approval_kind, summary_json, call_hash_hex, status)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending')",
                    params![
                        id.to_string(),
                        created_at.to_rfc3339(),
                        expires_at.to_rfc3339(),
                        tool_id_s,
                        reason_s,
                        kind_s,
                        summary_json,
                        call_hash_hex,
                    ],
                )?;
                Ok(())
            })
            .await?;

        Ok(ApprovalRequest {
            id,
            created_at,
            expires_at,
            tool_id: tool_id.to_string(),
            reason: reason.to_string(),
            kind,
            summary,
        })
    }

    pub async fn list_approvals(&self) -> anyhow::Result<Vec<ApprovalRequest>> {
        self.conn
            .call(|conn| {
                // Expire approvals opportunistically.
                let now = Utc::now().to_rfc3339();
                conn.execute(
                    "UPDATE approvals SET status='expired' WHERE status='pending' AND expires_at_rfc3339 < ?1",
                    params![now],
                )?;

                let mut stmt = conn.prepare(
                    "SELECT id, created_at_rfc3339, expires_at_rfc3339, tool_id, reason, approval_kind, summary_json
                     FROM approvals WHERE status='pending' ORDER BY created_at_rfc3339 DESC LIMIT 100",
                )?;
                let rows = stmt.query_map([], |row| {
                    let id: String = row.get(0)?;
                    let created_at: String = row.get(1)?;
                    let expires_at: String = row.get(2)?;
                    let tool_id: String = row.get(3)?;
                    let reason: String = row.get(4)?;
                    let kind: String = row.get(5)?;
                    let kind = match kind.as_str() {
                        "mobile_signer" => ApprovalKind::MobileSigner,
                        _ => ApprovalKind::Local,
                    };

                    let summary_json: String = row.get(6)?;
                    let summary: serde_json::Value =
                        serde_json::from_str(&summary_json).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                6,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?;

                    let created_at = created_at.parse::<DateTime<Utc>>().map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                    let expires_at = expires_at.parse::<DateTime<Utc>>().map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;

                    Ok(ApprovalRequest {
                        id: Uuid::parse_str(&id).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?,
                        created_at,
                        expires_at,
                        tool_id,
                        reason,
                        kind,
                        summary,
                    })
                })?;

                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await
            .map_err(Into::into)
    }

    pub async fn approval_kind(&self, id: Uuid) -> anyhow::Result<Option<ApprovalKind>> {
        let id_s = id.to_string();
        self.conn
            .call(move |conn| {
                let row: Option<String> = conn
                    .query_row(
                        "SELECT approval_kind FROM approvals WHERE id=?1",
                        params![id_s],
                        |r| r.get(0),
                    )
                    .optional()?;
                Ok(row.map(|s| {
                    if s == "mobile_signer" {
                        ApprovalKind::MobileSigner
                    } else {
                        ApprovalKind::Local
                    }
                }))
            })
            .await
            .map_err(Into::into)
    }

    pub async fn approve(&self, id: Uuid) -> anyhow::Result<Option<String>> {
        let id_s = id.to_string();
        let res = self
            .conn
            .call(move |conn| {
                let row: Option<(String, String)> = conn
                    .query_row(
                        "SELECT status, expires_at_rfc3339 FROM approvals WHERE id=?1",
                        params![id_s],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;

                let Some((status, expires_at)) = row else {
                    return Ok(None);
                };

                if status != "pending" {
                    return Ok(Some(id.to_string()));
                }

                let expires_at = expires_at.parse::<DateTime<Utc>>().map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;

                if Utc::now() > expires_at {
                    conn.execute(
                        "UPDATE approvals SET status='expired' WHERE id=?1",
                        params![id.to_string()],
                    )?;
                    return Ok(None);
                }

                conn.execute(
                    "UPDATE approvals SET status='approved' WHERE id=?1",
                    params![id.to_string()],
                )?;

                Ok(Some(id.to_string()))
            })
            .await?;

        Ok(res)
    }

    pub async fn is_approval_valid_for_call(
        &self,
        id: Uuid,
        tool_id: &str,
        args: &serde_json::Value,
    ) -> anyhow::Result<bool> {
        let id_s = id.to_string();
        let tool_id_s = tool_id.to_string();
        let call_hash_hex = sha256_hex(
            serde_json::to_vec(&serde_json::json!({"tool_id": tool_id, "args": args}))?.as_slice(),
        );

        self.conn
            .call(move |conn| {
                let row: Option<(String, String, String, String)> = conn
                    .query_row(
                        "SELECT status, expires_at_rfc3339, tool_id, call_hash_hex FROM approvals WHERE id=?1",
                        params![id_s],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional()?;

                let Some((status, expires_at, stored_tool_id, stored_call_hash_hex)) = row else {
                    return Ok(false);
                };

                if stored_tool_id != tool_id_s || stored_call_hash_hex != call_hash_hex {
                    return Ok(false);
                }

                let expires_at = expires_at.parse::<DateTime<Utc>>().map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;

                if Utc::now() > expires_at {
                    return Ok(false);
                }

                Ok(status == "approved")
            })
            .await
            .map_err(Into::into)
    }

    pub async fn upsert_tool_manifest(&self, manifest: &ToolManifest) -> anyhow::Result<()> {
        let tool_id = manifest.tool_id.clone();
        let runtime = match manifest.runtime {
            ToolRuntimeKind::Builtin => "builtin",
            ToolRuntimeKind::Wasm => "wasm",
            ToolRuntimeKind::RemoteMcp => "remote_mcp",
        }
        .to_string();
        let allowed_hosts_json = serde_json::to_string(&manifest.egress.allowed_hosts)?;
        let allowed_http_path_prefixes_json =
            serde_json::to_string(&manifest.egress.allowed_http_path_prefixes)?;
        let allowed_fs_path_prefixes_json =
            serde_json::to_string(&manifest.filesystem.allowed_path_prefixes)?;
        let max_output_bytes_i64 =
            i64::try_from(manifest.limits.max_output_bytes).unwrap_or(i64::MAX);
        let updated_at = Utc::now().to_rfc3339();

        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO tool_manifests(
                      tool_id,
                      runtime,
                      allowed_hosts_json,
                      allowed_http_path_prefixes_json,
                      allowed_fs_path_prefixes_json,
                      max_output_bytes,
                      updated_at_rfc3339
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    ON CONFLICT(tool_id) DO UPDATE SET
                      runtime=excluded.runtime,
                      allowed_hosts_json=excluded.allowed_hosts_json,
                      allowed_http_path_prefixes_json=excluded.allowed_http_path_prefixes_json,
                      allowed_fs_path_prefixes_json=excluded.allowed_fs_path_prefixes_json,
                      max_output_bytes=excluded.max_output_bytes,
                      updated_at_rfc3339=excluded.updated_at_rfc3339
                    "#,
                    params![
                        tool_id,
                        runtime,
                        allowed_hosts_json,
                        allowed_http_path_prefixes_json,
                        allowed_fs_path_prefixes_json,
                        max_output_bytes_i64,
                        updated_at
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn get_tool_manifest(&self, tool_id: &str) -> anyhow::Result<Option<ToolManifest>> {
        let tool_id = tool_id.to_string();
        self.conn
            .call(move |conn| {
                let row: Option<(String, String, String, String, String, i64)> = conn
                    .query_row(
                        r#"
                        SELECT tool_id, runtime, allowed_hosts_json, allowed_http_path_prefixes_json, allowed_fs_path_prefixes_json, max_output_bytes
                        FROM tool_manifests
                        WHERE tool_id=?1
                        "#,
                        params![tool_id],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                    )
                    .optional()?;

                let Some((tool_id, runtime_s, allowed_hosts_json, allowed_http_paths_json, allowed_fs_paths_json, max_output_bytes_i64)) = row else {
                    return Ok(None);
                };

                let runtime = match runtime_s.as_str() {
                    "builtin" => ToolRuntimeKind::Builtin,
                    "wasm" => ToolRuntimeKind::Wasm,
                    "remote_mcp" => ToolRuntimeKind::RemoteMcp,
                    _other => {
                        // Fail-closed: treat unknown runtime values as "missing manifest".
                        return Ok(None);
                    }
                };

                let allowed_hosts: Vec<String> =
                    serde_json::from_str(&allowed_hosts_json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                let allowed_http_path_prefixes: Vec<String> =
                    serde_json::from_str(&allowed_http_paths_json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                let allowed_path_prefixes: Vec<String> =
                    serde_json::from_str(&allowed_fs_paths_json).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                let max_output_bytes_u64 = u64::try_from(max_output_bytes_i64)
                    .unwrap_or(0);

                Ok(Some(ToolManifest {
                    tool_id,
                    runtime,
                    egress: ToolEgressPolicy {
                        allowed_hosts,
                        allowed_http_path_prefixes,
                    },
                    filesystem: ToolFilesystemPolicy {
                        allowed_path_prefixes,
                    },
                    limits: ToolLimits {
                        max_output_bytes: max_output_bytes_u64,
                    },
                }))
            })
            .await
            .map_err(Into::into)
    }
}
