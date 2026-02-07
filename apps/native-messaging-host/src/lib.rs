use anyhow::Context as _;
use briefcase_api::BriefcaseClient;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tracing::error;

pub const MAX_MESSAGE_SIZE_BYTES: usize = 1024 * 1024; // 1 MiB

#[derive(Debug, Deserialize)]
pub struct NativeRequest {
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct NativeResponse {
    pub id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn run_native_messaging_host<R, W>(
    client: &BriefcaseClient,
    reader: &mut R,
    writer: &mut W,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("read message length"),
        }

        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_MESSAGE_SIZE_BYTES {
            let resp = NativeResponse {
                id: "unknown".to_string(),
                ok: false,
                result: None,
                error: Some("invalid_message_size".to_string()),
            };
            write_msg(writer, &resp).await?;
            continue;
        }

        let mut msg = vec![0u8; len];
        reader.read_exact(&mut msg).await.context("read message")?;

        let req: NativeRequest = match serde_json::from_slice(&msg) {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, "decode native request failed");
                let resp = NativeResponse {
                    id: "unknown".to_string(),
                    ok: false,
                    result: None,
                    error: Some("invalid_json".to_string()),
                };
                write_msg(writer, &resp).await?;
                continue;
            }
        };

        let id = req.id.clone();
        let resp = match handle(client, req).await {
            Ok(v) => v,
            Err(e) => {
                error!(error = %e, request_id = %id, "native request failed");
                NativeResponse {
                    id,
                    ok: false,
                    result: None,
                    error: Some("internal_error".to_string()),
                }
            }
        };
        write_msg(writer, &resp).await?;
    }

    Ok(())
}

async fn write_msg<W: AsyncWrite + Unpin>(
    writer: &mut W,
    resp: &NativeResponse,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(resp).context("encode response json")?;
    let len: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| anyhow::anyhow!("response too large"))?;
    writer
        .write_all(&len.to_le_bytes())
        .await
        .context("write response length")?;
    writer
        .write_all(&bytes)
        .await
        .context("write response bytes")?;
    writer.flush().await.context("flush response")?;
    Ok(())
}

async fn handle(client: &BriefcaseClient, req: NativeRequest) -> anyhow::Result<NativeResponse> {
    let id = req.id.clone();

    macro_rules! ok_json {
        ($val:expr) => {{
            NativeResponse {
                id,
                ok: true,
                result: Some(serde_json::to_value($val).context("serialize result")?),
                error: None,
            }
        }};
    }

    #[derive(Debug, Deserialize)]
    struct UpsertMcpServerParams {
        server_id: String,
        endpoint_url: String,
    }

    #[derive(Debug, Deserialize)]
    struct DeleteMcpServerParams {
        server_id: String,
    }

    #[derive(Debug, Deserialize)]
    struct RevokeMcpOauthParams {
        server_id: String,
    }

    #[derive(Debug, Deserialize)]
    struct UpsertProviderParams {
        provider_id: String,
        base_url: String,
    }

    #[derive(Debug, Deserialize)]
    struct FetchVcParams {
        provider_id: String,
    }

    #[derive(Debug, Deserialize)]
    struct DeleteProviderParams {
        provider_id: String,
    }

    #[derive(Debug, Deserialize)]
    struct RevokeProviderOauthParams {
        provider_id: String,
    }

    #[derive(Debug, Deserialize)]
    struct SetBudgetParams {
        category: String,
        daily_limit_microusd: i64,
    }

    #[derive(Debug, Deserialize)]
    struct PolicyCompileParams {
        prompt: String,
    }

    #[derive(Debug, Deserialize)]
    struct PolicyApplyParams {
        proposal_id: String,
    }

    #[derive(Debug, Deserialize)]
    struct ApproveParams {
        id: String,
    }

    #[derive(Debug, Deserialize)]
    struct ListReceiptsParams {
        #[serde(default)]
        limit: Option<u32>,
        #[serde(default)]
        offset: Option<u32>,
    }

    #[derive(Debug, Deserialize)]
    struct AiAnomaliesParams {
        #[serde(default)]
        limit: Option<u32>,
    }

    #[derive(Debug, Deserialize)]
    struct ControlPlaneEnrollParams {
        base_url: String,
        admin_token: String,
        device_name: String,
    }

    #[derive(Debug, Deserialize)]
    struct McpOAuthStartParams {
        server_id: String,
        client_id: String,
        redirect_uri: String,
        #[serde(default)]
        scope: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct McpOAuthExchangeParams {
        server_id: String,
        code: String,
        state: String,
    }

    match req.method.as_str() {
        "health" => {
            client.health().await?;
            Ok(ok_json!(serde_json::json!({ "status": "ok" })))
        }
        "identity" => Ok(ok_json!(client.identity().await?)),
        "control_plane_status" => Ok(ok_json!(client.control_plane_status().await?)),
        "control_plane_enroll" => {
            let p: ControlPlaneEnrollParams =
                serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(
                client
                    .control_plane_enroll(briefcase_api::types::ControlPlaneEnrollRequest {
                        base_url: p.base_url,
                        admin_token: p.admin_token,
                        device_name: p.device_name,
                    })
                    .await?
            ))
        }
        "control_plane_sync" => Ok(ok_json!(client.control_plane_sync().await?)),
        "list_tools" => Ok(ok_json!(client.list_tools().await?)),
        "list_providers" => Ok(ok_json!(client.list_providers().await?)),
        "upsert_provider" => {
            let p: UpsertProviderParams =
                serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(
                client.upsert_provider(&p.provider_id, p.base_url).await?
            ))
        }
        "fetch_vc" => {
            let p: FetchVcParams = serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(client.fetch_vc(&p.provider_id).await?))
        }
        "delete_provider" => {
            let p: DeleteProviderParams =
                serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(client.delete_provider(&p.provider_id).await?))
        }
        "revoke_provider_oauth" => {
            let p: RevokeProviderOauthParams =
                serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(
                client.revoke_provider_oauth(&p.provider_id).await?
            ))
        }
        "list_mcp_servers" => Ok(ok_json!(client.list_mcp_servers().await?)),
        "upsert_mcp_server" => {
            let p: UpsertMcpServerParams =
                serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(
                client
                    .upsert_mcp_server(&p.server_id, p.endpoint_url)
                    .await?
            ))
        }
        "delete_mcp_server" => {
            let p: DeleteMcpServerParams =
                serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(client.delete_mcp_server(&p.server_id).await?))
        }
        "revoke_mcp_oauth" => {
            let p: RevokeMcpOauthParams =
                serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(client.revoke_mcp_oauth(&p.server_id).await?))
        }
        "mcp_oauth_start" => {
            let p: McpOAuthStartParams =
                serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(
                client
                    .mcp_oauth_start(
                        &p.server_id,
                        briefcase_api::types::McpOAuthStartRequest {
                            client_id: p.client_id,
                            redirect_uri: p.redirect_uri,
                            scope: p.scope,
                        },
                    )
                    .await?
            ))
        }
        "mcp_oauth_exchange" => {
            let p: McpOAuthExchangeParams =
                serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(
                client
                    .mcp_oauth_exchange(
                        &p.server_id,
                        briefcase_api::types::McpOAuthExchangeRequest {
                            code: p.code,
                            state: p.state,
                        },
                    )
                    .await?
            ))
        }
        "list_budgets" => Ok(ok_json!(client.list_budgets().await?)),
        "set_budget" => {
            let p: SetBudgetParams = serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(
                client
                    .set_budget(&p.category, p.daily_limit_microusd)
                    .await?
            ))
        }
        "policy_get" => Ok(ok_json!(client.policy_get().await?)),
        "policy_compile" => {
            let p: PolicyCompileParams =
                serde_json::from_value(req.params).context("parse params")?;
            Ok(ok_json!(
                client
                    .policy_compile(briefcase_api::types::PolicyCompileRequest { prompt: p.prompt })
                    .await?
            ))
        }
        "policy_apply" => {
            let p: PolicyApplyParams =
                serde_json::from_value(req.params).context("parse params")?;
            let proposal_id =
                uuid::Uuid::parse_str(&p.proposal_id).context("invalid proposal id")?;
            Ok(ok_json!(client.policy_apply(&proposal_id).await?))
        }
        "list_approvals" => Ok(ok_json!(client.list_approvals().await?)),
        "approve" => {
            let p: ApproveParams = serde_json::from_value(req.params).context("parse params")?;
            let id = uuid::Uuid::parse_str(&p.id).context("invalid approval id")?;
            Ok(ok_json!(client.approve(&id).await?))
        }
        "list_receipts" => {
            let p: ListReceiptsParams =
                serde_json::from_value(req.params).context("parse params")?;
            let limit = p.limit.unwrap_or(50);
            let offset = p.offset.unwrap_or(0);
            Ok(ok_json!(client.list_receipts_paged(limit, offset).await?))
        }
        "verify_receipts" => Ok(ok_json!(client.verify_receipts().await?)),
        "ai_anomalies" => {
            let p: AiAnomaliesParams =
                serde_json::from_value(req.params).context("parse params")?;
            let limit = p.limit.unwrap_or(200);
            Ok(ok_json!(client.ai_anomalies(limit).await?))
        }
        other => Ok(NativeResponse {
            id,
            ok: false,
            result: None,
            error: Some(format!("unknown_method:{other}")),
        }),
    }
}
