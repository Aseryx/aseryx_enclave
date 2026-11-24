//! Releasing the dataset key: a call to the decrypt Lit Action with the owner's consent and the workload's attestation,
//! and opening the answer with the workload's response key.
//!
//! The action checks everything: the consent's signer, the workload identity, the job, the firmware. This client only
//! forwards the proof and opens what comes back, which is sealed to a key that exists inside this container.

use crate::consent::Bytes32;
use crate::keys::ResponseKey;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR};
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const RESPONSE_DOMAIN: &str = "aseryx/attested-key-response/v1";

/// Why the key was not released.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum LitError {
    /// The action refused: a consent, token or key did not satisfy it.
    #[error("the decrypt action refused")]
    Denied,
    /// Lit could not be reached, answered with an error, or answered with something that is not a sealed key.
    #[error("the decrypt action could not be run")]
    Transport,
    /// The sealed answer does not open with this workload's response key for this consent.
    #[error("the sealed answer does not open")]
    Open,
}

/// A key sealed by the action to the workload's response key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SealedResponse {
    /// The HPKE encapsulated key, base64url without padding.
    pub enc: String,
    /// The HPKE ciphertext of the 32-byte key, base64url without padding.
    pub ciphertext: String,
}

/// Something that can have the decrypt action release the dataset key to this workload.
pub trait KeyReleaser {
    /// Sends `request`, which carries token 2, the runtime data and the sealed key, and returns the sealed answer.
    ///
    /// # Errors
    ///
    /// [`LitError::Denied`] when the API or the action refuses and [`LitError::Transport`] for anything else that goes wrong.
    fn release(&self, request: &Value) -> Result<SealedResponse, LitError>;
}

/// Opens a sealed key with the workload's response key. `consent_digest` is the digest of the consent that released it,
/// which the action bound into the seal.
///
/// # Errors
///
/// [`LitError::Open`] for a sealed key of another shape, for another response key or for another consent.
pub fn open_attested_response(
    key: &ResponseKey,
    sealed: &SealedResponse,
    consent_digest: &Bytes32,
) -> Result<[u8; 32], LitError> {
    let enc = URL_SAFE_NO_PAD
        .decode(&sealed.enc)
        .map_err(|_| LitError::Open)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&sealed.ciphertext)
        .map_err(|_| LitError::Open)?;
    let encapped =
        <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&enc).map_err(|_| LitError::Open)?;
    let info = format!(r#"{{"consent":"{consent_digest}","domain":"{RESPONSE_DOMAIN}"}}"#);
    let opened = hpke::single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        key.private(),
        &encapped,
        info.as_bytes(),
        &ciphertext,
        &[],
    )
    .map_err(|_| LitError::Open)?;
    opened.try_into().map_err(|_| LitError::Open)
}

#[derive(Deserialize)]
struct ActionOutput {
    ok: bool,
    sealed: Option<SealedResponse>,
}

/// The API's relay to the decrypt action.
///
/// The workload holds no Lit credential. It posts token 2, the runtime data and the sealed key to the API's
/// `attested-appraisal` function, which checks them as for any call of the job, builds every other parameter of the action
/// from the job's own record, runs the pinned action, and returns the action's answer unchanged. The answer is sealed to
/// this workload's response key, which the API never holds.
pub struct ApiRelay {
    url: String,
    agent: ureq::Agent,
}

impl ApiRelay {
    /// A client of the relay at `url`, the `attested-appraisal` function.
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

impl KeyReleaser for ApiRelay {
    fn release(&self, request: &Value) -> Result<SealedResponse, LitError> {
        let mut response = self
            .agent
            .post(&self.url)
            .send_json(request)
            .map_err(|_| LitError::Transport)?;
        match response.status().as_u16() {
            200 => {}
            403 => return Err(LitError::Denied),
            _ => return Err(LitError::Transport),
        }
        let output: ActionOutput = response
            .body_mut()
            .read_json()
            .map_err(|_| LitError::Transport)?;
        match (output.ok, output.sealed) {
            (true, Some(sealed)) => Ok(sealed),
            (false, None) => Err(LitError::Denied),
            _ => Err(LitError::Transport),
        }
    }
}
