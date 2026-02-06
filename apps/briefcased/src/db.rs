use std::path::Path;

use anyhow::Context as _;
use briefcase_core::{ApprovalRequest, util::sha256_hex};
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
    pub resource: String,
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

                    CREATE TABLE IF NOT EXISTS identity (
                      id                INTEGER PRIMARY KEY CHECK (id = 1),
                      did               TEXT NOT NULL,
                      created_at_rfc3339 TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS vcs (
                      provider_id           TEXT PRIMARY KEY,
                      vc_jwt                TEXT NOT NULL,
                      expires_at_rfc3339    TEXT NOT NULL,
                      created_at_rfc3339    TEXT NOT NULL
                    );

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
                      resource              TEXT NOT NULL,
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
                    "#,
                )?;
                Ok(())
            })
            .await?;

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

    pub async fn upsert_remote_mcp_oauth(
        &self,
        server_id: &str,
        issuer: &str,
        authorization_endpoint: &str,
        token_endpoint: &str,
        resource: &str,
    ) -> anyhow::Result<()> {
        let server_id = server_id.to_string();
        let issuer = issuer.to_string();
        let authorization_endpoint = authorization_endpoint.to_string();
        let token_endpoint = token_endpoint.to_string();
        let resource = resource.to_string();
        let discovered_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO remote_mcp_oauth(server_id, issuer, authorization_endpoint, token_endpoint, resource, discovered_at_rfc3339)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                    ON CONFLICT(server_id) DO UPDATE SET
                      issuer=excluded.issuer,
                      authorization_endpoint=excluded.authorization_endpoint,
                      token_endpoint=excluded.token_endpoint,
                      resource=excluded.resource,
                      discovered_at_rfc3339=excluded.discovered_at_rfc3339
                    "#,
                    params![
                        server_id,
                        issuer,
                        authorization_endpoint,
                        token_endpoint,
                        resource,
                        discovered_at
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
                        SELECT server_id, issuer, authorization_endpoint, token_endpoint, resource
                        FROM remote_mcp_oauth
                        WHERE server_id=?1
                        "#,
                        params![server_id],
                        |row| {
                            Ok(RemoteMcpOauthRecord {
                                server_id: row.get(0)?,
                                issuer: row.get(1)?,
                                authorization_endpoint: row.get(2)?,
                                token_endpoint: row.get(3)?,
                                resource: row.get(4)?,
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

    pub async fn upsert_vc(
        &self,
        provider_id: &str,
        vc_jwt: &str,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let provider_id = provider_id.to_string();
        let vc_jwt = vc_jwt.to_string();
        let expires_at_rfc3339 = expires_at.to_rfc3339();
        let created_at = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    r#"
                    INSERT INTO vcs(provider_id, vc_jwt, expires_at_rfc3339, created_at_rfc3339)
                    VALUES (?1, ?2, ?3, ?4)
                    ON CONFLICT(provider_id) DO UPDATE SET vc_jwt=excluded.vc_jwt, expires_at_rfc3339=excluded.expires_at_rfc3339
                    "#,
                    params![provider_id, vc_jwt, expires_at_rfc3339, created_at],
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
                        "SELECT vc_jwt, expires_at_rfc3339 FROM vcs WHERE provider_id=?1",
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

    pub async fn create_approval(
        &self,
        tool_id: &str,
        reason: &str,
        args: &serde_json::Value,
    ) -> anyhow::Result<ApprovalRequest> {
        let id = Uuid::new_v4();
        let created_at = Utc::now();
        let expires_at = created_at + Duration::minutes(10);

        let tool_id_s = tool_id.to_string();
        let reason_s = reason.to_string();
        let summary = serde_json::json!({
            "tool_id": tool_id,
            "reason": reason,
            "args_hash": sha256_hex(serde_json::to_vec(args)?.as_slice()),
        });
        let summary_json = serde_json::to_string(&summary)?;
        let call_hash_hex = sha256_hex(
            serde_json::to_vec(&serde_json::json!({"tool_id": tool_id, "args": args}))?.as_slice(),
        );

        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO approvals(id, created_at_rfc3339, expires_at_rfc3339, tool_id, reason, summary_json, call_hash_hex, status)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending')",
                    params![
                        id.to_string(),
                        created_at.to_rfc3339(),
                        expires_at.to_rfc3339(),
                        tool_id_s,
                        reason_s,
                        summary_json,
                        call_hash_hex
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
                    "SELECT id, created_at_rfc3339, expires_at_rfc3339, tool_id, reason, summary_json
                     FROM approvals WHERE status='pending' ORDER BY created_at_rfc3339 DESC LIMIT 100",
                )?;
                let rows = stmt.query_map([], |row| {
                    let id: String = row.get(0)?;
                    let created_at: String = row.get(1)?;
                    let expires_at: String = row.get(2)?;
                    let tool_id: String = row.get(3)?;
                    let reason: String = row.get(4)?;
                    let summary_json: String = row.get(5)?;
                    let summary: serde_json::Value =
                        serde_json::from_str(&summary_json).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                5,
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
                        summary,
                    })
                })?;

                Ok(rows.collect::<Result<Vec<_>, _>>()?)
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
}
