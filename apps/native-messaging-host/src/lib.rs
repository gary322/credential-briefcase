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
        other => Ok(NativeResponse {
            id,
            ok: false,
            result: None,
            error: Some(format!("unknown_method:{other}")),
        }),
    }
}
