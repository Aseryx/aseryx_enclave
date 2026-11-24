//! Claiming a job with two attestations.
//!
//! The job id cannot be in the container's environment, because that would change the policy hash per job. The workload
//! starts with no job data, generates its keys, and attests them (token 1). The API verifies token 1 and assigns the
//! oldest unclaimed job that fits. The workload then attests the same keys with the job id (token 2), which is the token
//! the decrypt action checks.

use crate::attest::Attestor;
use crate::consent::Bytes32;
use crate::error_code::ErrorCode;
use crate::keys::{ResponseKey, ResultKey};
use crate::runtime_data::RuntimeData;

/// Why the API did not assign a job.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum ClaimError {
    /// The API could not be reached or did not answer.
    #[error("the API did not answer the claim")]
    Transport,
    /// The API refused the token or had no job for this container.
    #[error("the API refused the claim")]
    Refused,
}

/// Where a workload asks for its job.
pub trait JobSource {
    /// Presents token 1 and the memory the container can see, in gigabytes. Returns the job id assigned.
    ///
    /// # Errors
    ///
    /// A [`ClaimError`] if no job was assigned.
    fn claim(&self, token: &str, memory_gb: u32) -> Result<Bytes32, ClaimError>;
}

/// A claimed job and everything the workload needs to carry it out.
pub struct Claimed {
    /// The job id the API assigned.
    pub job_id: Bytes32,
    /// Token 2: the attestation of the keys and the job id.
    pub token: String,
    /// The exact runtime data token 2 attests, which the decrypt action hashes and checks.
    pub runtime_data: RuntimeData,
    /// The key the dataset key is sealed to.
    pub response_key: ResponseKey,
    /// The key that signs the result.
    pub result_key: ResultKey,
}

/// Generates the keys, attests them, claims a job, and attests the keys again with the job id.
///
/// # Errors
///
/// [`ErrorCode::AttestationFailed`] if a key or a token could not be obtained, and [`ErrorCode::ClaimFailed`] if the API
/// assigned no job. The API is not asked again after an attestation failure, and no second token is requested after a
/// refused claim.
pub fn claim_job(
    attestor: &dyn Attestor,
    source: &dyn JobSource,
    memory_gb: u32,
) -> Result<Claimed, ErrorCode> {
    let response_key = ResponseKey::generate().map_err(|_| ErrorCode::AttestationFailed)?;
    let result_key = ResultKey::generate().map_err(|_| ErrorCode::AttestationFailed)?;
    let claim = RuntimeData::claim(&response_key.public_hex(), &result_key.public_hex());
    let first = attestor
        .attest(&claim)
        .map_err(|_| ErrorCode::AttestationFailed)?;
    let job_id = source
        .claim(&first, memory_gb)
        .map_err(|_| ErrorCode::ClaimFailed)?;
    let runtime_data = claim.for_job(&job_id);
    let token = attestor
        .attest(&runtime_data)
        .map_err(|_| ErrorCode::AttestationFailed)?;
    Ok(Claimed {
        job_id,
        token,
        runtime_data,
        response_key,
        result_key,
    })
}
