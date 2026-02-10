use anyhow::Context as _;
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::Url;
use uuid::Uuid;

use crate::types::{
    AdminSetPolicyRequest, AdminSetPolicyResponse, AuditListReceiptsResponse, DevicePolicyResponse,
    DeviceRemoteSignerResponse, EnrollDeviceRequest, EnrollDeviceResponse, ErrorResponse,
    HealthResponse, RemoteSignRequest, RemoteSignResponse, UploadReceiptsRequest,
    UploadReceiptsResponse,
};

#[derive(Debug, Clone)]
pub struct ControlPlaneClient {
    base_url: Url,
    http: reqwest::Client,
}

impl ControlPlaneClient {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        let base_url = Url::parse(base_url).context("parse base_url")?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build reqwest client")?;
        Ok(Self { base_url, http })
    }

    pub async fn health(&self) -> anyhow::Result<HealthResponse> {
        self.get_json("/health", None::<&str>, None).await
    }

    pub async fn admin_set_policy(
        &self,
        admin_token: &str,
        req: AdminSetPolicyRequest,
    ) -> anyhow::Result<AdminSetPolicyResponse> {
        self.post_json("/v1/admin/policy", Some(admin_token), None, req)
            .await
    }

    pub async fn admin_enroll_device(
        &self,
        admin_token: &str,
        req: EnrollDeviceRequest,
    ) -> anyhow::Result<EnrollDeviceResponse> {
        self.post_json("/v1/admin/devices/enroll", Some(admin_token), None, req)
            .await
    }

    pub async fn device_get_policy(
        &self,
        device_id: &Uuid,
        device_token: &str,
        dpop_proof: Option<&str>,
    ) -> anyhow::Result<DevicePolicyResponse> {
        self.get_json(
            &format!("/v1/devices/{device_id}/policy"),
            Some(device_token),
            dpop_proof,
        )
        .await
    }

    pub async fn device_upload_receipts(
        &self,
        device_id: &Uuid,
        device_token: &str,
        dpop_proof: Option<&str>,
        req: UploadReceiptsRequest,
    ) -> anyhow::Result<UploadReceiptsResponse> {
        self.post_json(
            &format!("/v1/devices/{device_id}/receipts"),
            Some(device_token),
            dpop_proof,
            req,
        )
        .await
    }

    pub async fn device_remote_signer(
        &self,
        device_id: &Uuid,
        device_token: &str,
    ) -> anyhow::Result<DeviceRemoteSignerResponse> {
        self.get_json(
            &format!("/v1/devices/{device_id}/remote-signer"),
            Some(device_token),
            None,
        )
        .await
    }

    pub async fn device_remote_sign(
        &self,
        device_id: &Uuid,
        device_token: &str,
        req: RemoteSignRequest,
    ) -> anyhow::Result<RemoteSignResponse> {
        self.post_json(
            &format!("/v1/devices/{device_id}/remote-signer/sign"),
            Some(device_token),
            None,
            req,
        )
        .await
    }

    pub async fn audit_list_receipts(
        &self,
        auditor_token: &str,
        device_id: Option<&Uuid>,
        limit: u32,
        offset: u32,
    ) -> anyhow::Result<AuditListReceiptsResponse> {
        let mut url = self
            .base_url
            .join("/v1/audit/receipts")
            .context("join url")?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("limit", &limit.min(1000).to_string());
            qp.append_pair("offset", &offset.to_string());
            if let Some(id) = device_id {
                qp.append_pair("device_id", &id.to_string());
            }
        }
        self.get_json_absolute(url, Some(auditor_token), None).await
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        dpop_proof: Option<&str>,
    ) -> anyhow::Result<T> {
        let url = self.base_url.join(path).context("join url")?;
        self.get_json_absolute(url, token, dpop_proof).await
    }

    async fn get_json_absolute<T: DeserializeOwned>(
        &self,
        url: Url,
        token: Option<&str>,
        dpop_proof: Option<&str>,
    ) -> anyhow::Result<T> {
        let mut req = self.http.get(url).header("accept", "application/json");
        if let Some(t) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(p) = dpop_proof {
            req = req.header("dpop", p);
        }
        let resp = req.send().await.context("send request")?;
        parse_json_response(resp).await
    }

    async fn post_json<Req: Serialize, Res: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        dpop_proof: Option<&str>,
        body: Req,
    ) -> anyhow::Result<Res> {
        let url = self.base_url.join(path).context("join url")?;
        let mut req = self
            .http
            .post(url)
            .header("accept", "application/json")
            .json(&body);
        if let Some(t) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(p) = dpop_proof {
            req = req.header("dpop", p);
        }
        let resp = req.send().await.context("send request")?;
        parse_json_response(resp).await
    }
}

async fn parse_json_response<T: DeserializeOwned>(resp: reqwest::Response) -> anyhow::Result<T> {
    let status = resp.status();
    let bytes = resp.bytes().await.context("read response bytes")?;
    if !status.is_success() {
        if let Ok(err) = serde_json::from_slice::<ErrorResponse>(&bytes) {
            anyhow::bail!("control plane error {}: {}", err.code, err.message);
        }
        anyhow::bail!(
            "control plane http error {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    let out = serde_json::from_slice::<T>(&bytes).context("decode response json")?;
    Ok(out)
}
