//! The error codes a workload reports for a job.
//!
//! The container policy blocks shell, exec and stdio, so a failure is reported as one code and nothing else. A code
//! carries no data and no text from the file.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Why a job did not produce a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// An attestation token could not be obtained from the sidecar.
    AttestationFailed,
    /// The API refused or could not answer the job claim.
    ClaimFailed,
    /// The decrypt action refused to release the key.
    KeyDenied,
    /// The manifest, a chunk or the on-chain record could not be fetched.
    FetchFailed,
    /// The decrypted bytes do not hash to the registered plaintext hash.
    HashMismatch,
    /// The projected time exceeds the job's ceiling.
    TooLarge,
    /// The engine could not appraise or count the file.
    AppraiseFailed,
    /// The proof could not be generated.
    ProveFailed,
    /// The signed result could not be delivered.
    UploadFailed,
}

impl ErrorCode {
    /// Every code, in the order the plan lists them.
    pub const ALL: [Self; 9] = [
        Self::AttestationFailed,
        Self::ClaimFailed,
        Self::KeyDenied,
        Self::FetchFailed,
        Self::HashMismatch,
        Self::TooLarge,
        Self::AppraiseFailed,
        Self::ProveFailed,
        Self::UploadFailed,
    ];

    /// The code as it appears on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttestationFailed => "attestation_failed",
            Self::ClaimFailed => "claim_failed",
            Self::KeyDenied => "key_denied",
            Self::FetchFailed => "fetch_failed",
            Self::HashMismatch => "hash_mismatch",
            Self::TooLarge => "too_large",
            Self::AppraiseFailed => "appraise_failed",
            Self::ProveFailed => "prove_failed",
            Self::UploadFailed => "upload_failed",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Text that is not an error code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not an error code: {0}")]
pub struct ParseErrorCodeError(String);

impl FromStr for ErrorCode {
    type Err = ParseErrorCodeError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|code| code.as_str() == text)
            .ok_or_else(|| ParseErrorCodeError(text.chars().take(40).collect()))
    }
}
