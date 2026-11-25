//! The client of the API's `attested-appraisal` function.

use crate::claim::{ClaimError, JobSource};
use crate::consent::Bytes32;
use crate::job::{ApiError, JobApi, JobInputs};
use crate::runtime_data::RuntimeData;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const JOB_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClaimRequest<'a> {
    action: &'static str,
    token: &'a str,
    runtime_data: String,
    memory_gb: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaimReply {
    job_id: String,
}

/// The API's `attested-appraisal` function, reached over HTTP.
pub struct ApiJobSource {
    url: String,
    agent: ureq::Agent,
}

impl ApiJobSource {
    /// A client for the function at `url`, for example `https://<project>.supabase.co/functions/v1/attested-appraisal`.
    #[must_use]
    pub fn new(url: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            url: url.to_owned(),
            agent,
        }
    }
}

impl JobSource for ApiJobSource {
    fn claim(
        &self,
        token: &str,
        runtime_data: &RuntimeData,
        memory_gb: u32,
    ) -> Result<Bytes32, ClaimError> {
        let request = ClaimRequest {
            action: "claim",
            token,
            runtime_data: runtime_data.to_base64(),
            memory_gb,
        };
        let mut response = self
            .agent
            .post(&self.url)
            .send_json(&request)
            .map_err(|_| ClaimError::Transport)?;
        match response.status().as_u16() {
            200 => {
                let reply: ClaimReply = response
                    .body_mut()
                    .read_json()
                    .map_err(|_| ClaimError::Transport)?;
                Bytes32::parse(&reply.job_id).map_err(|_| ClaimError::Transport)
            }
            404 => Err(ClaimError::NoJob),
            400 | 403 => Err(ClaimError::Refused),
            _ => Err(ClaimError::Transport),
        }
    }
}

/// The API's `attested-appraisal` function after a claim: the job's inputs and its signed result.
pub struct ApiClient {
    url: String,
    agent: ureq::Agent,
}

impl ApiClient {
    /// A client for the function at `url`.
    #[must_use]
    pub fn new(url: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(JOB_TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            url: url.to_owned(),
            agent,
        }
    }

    fn post(&self, body: &Value) -> Result<ureq::http::Response<ureq::Body>, ApiError> {
        let response = self
            .agent
            .post(&self.url)
            .send_json(body)
            .map_err(|_| ApiError)?;
        if response.status().as_u16() == 200 {
            Ok(response)
        } else {
            Err(ApiError)
        }
    }
}

impl JobApi for ApiClient {
    fn job(&self, token: &str, runtime_data: &str) -> Result<JobInputs, ApiError> {
        let mut response =
            self.post(&json!({"action": "job", "token": token, "runtimeData": runtime_data}))?;
        response.body_mut().read_json().map_err(|_| ApiError)
    }

    fn post_result(&self, body: &Value) -> Result<(), ApiError> {
        self.post(body).map(drop)
    }
}
