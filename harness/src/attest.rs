//! The attestation client: asks the sidecar container for an Azure Attestation token that carries the workload's
//! runtime data.
//!
//! The sidecar listens on the container group's loopback interface. It signs nothing itself: it fetches the AMD
//! hardware report for the group, sends it to Azure Attestation with the runtime data, and returns Azure's token.

use crate::runtime_data::RuntimeData;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const ATTEST_PATH: &str = "/attest/maa";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a token could not be obtained.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestError {
    /// The sidecar could not be reached or the connection failed.
    #[error("the attestation sidecar could not be reached")]
    Transport,
    /// The sidecar answered with a status other than 200.
    #[error("the attestation sidecar answered {0}")]
    Status(u16),
    /// The answer was not a JSON object with a token of three dot-separated parts.
    #[error("the attestation sidecar's answer is not a token")]
    Body,
}

/// Something that can attest runtime data.
pub trait Attestor {
    /// Returns an Azure Attestation token whose runtime claim is `runtime_data`.
    ///
    /// # Errors
    ///
    /// An [`AttestError`] if no valid-looking token was obtained.
    fn attest(&self, runtime_data: &RuntimeData) -> Result<String, AttestError>;
}

#[derive(Serialize)]
struct Request<'a> {
    maa_endpoint: &'a str,
    runtime_data: String,
}

#[derive(Deserialize)]
struct Response {
    token: String,
}

/// The attestation sidecar of a confidential container group.
pub struct SidecarAttestor {
    base_url: String,
    maa_endpoint: String,
    agent: ureq::Agent,
}

impl SidecarAttestor {
    /// A client for the sidecar at `base_url` (for example `http://localhost:8080`) that asks the Azure Attestation
    /// service at `maa_endpoint` (a host name, for example `sharedeus.eus.attest.azure.net`) to issue the tokens.
    #[must_use]
    pub fn new(base_url: &str, maa_endpoint: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            maa_endpoint: maa_endpoint.to_owned(),
            agent,
        }
    }
}

impl Attestor for SidecarAttestor {
    fn attest(&self, runtime_data: &RuntimeData) -> Result<String, AttestError> {
        let request = Request {
            maa_endpoint: &self.maa_endpoint,
            runtime_data: runtime_data.to_base64(),
        };
        let mut response = self
            .agent
            .post(format!("{}{ATTEST_PATH}", self.base_url))
            .send_json(&request)
            .map_err(|_| AttestError::Transport)?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(AttestError::Status(status));
        }
        let body: Response = response
            .body_mut()
            .read_json()
            .map_err(|_| AttestError::Body)?;
        if body.token.split('.').count() != 3 || body.token.split('.').any(str::is_empty) {
            return Err(AttestError::Body);
        }
        Ok(body.token)
    }
}
