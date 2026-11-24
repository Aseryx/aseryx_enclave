//! The runtime data a workload attests: the bytes the attestation sidecar hashes into the report data and Azure returns
//! as the token's runtime claim.
//!
//! The workload serializes it once and sends exactly those bytes. Token 1, sent to claim a job, carries the two public
//! keys; token 2 carries the claimed job id as well.

use crate::consent::Bytes32;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;

/// The runtime data version.
pub const RUNTIME_DATA_VERSION: u8 = 1;

/// What a workload attests about itself and its job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeData {
    v: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    job_id: Option<String>,
    response_public_key: String,
    result_public_key: String,
}

impl RuntimeData {
    /// The runtime data of token 1: the two public keys, no job yet.
    #[must_use]
    pub fn claim(response_public_key: &str, result_public_key: &str) -> Self {
        Self {
            v: RUNTIME_DATA_VERSION,
            job_id: None,
            response_public_key: response_public_key.to_owned(),
            result_public_key: result_public_key.to_owned(),
        }
    }

    /// The runtime data of token 2: the same keys and the job the API assigned.
    #[must_use]
    pub fn for_job(&self, job_id: &Bytes32) -> Self {
        Self {
            job_id: Some(job_id.to_string()),
            ..self.clone()
        }
    }

    /// The exact bytes to attest.
    ///
    /// # Panics
    ///
    /// Never: the value is strings and a number, which always serialize.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("strings and a number always serialize")
    }

    /// The bytes as the standard base64 the sidecar takes.
    #[must_use]
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_bytes())
    }
}
