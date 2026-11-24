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
use serde_json::{Value, json};
use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const RESPONSE_DOMAIN: &str = "aseryx/attested-key-response/v1";

/// Why the key was not released.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
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

/// Something that can run the decrypt action with an `attestedDecrypt` request.
pub trait KeyReleaser {
    /// Runs the action with `params` and returns the sealed key.
    ///
    /// # Errors
    ///
    /// [`LitError::Denied`] when the action refuses and [`LitError::Transport`] for anything else that goes wrong.
    fn release(&self, params: &Value) -> Result<SealedResponse, LitError>;
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
struct ActionReply {
    #[serde(default)]
    has_error: bool,
    response: Option<ActionOutput>,
}

#[derive(Deserialize)]
struct ActionOutput {
    ok: bool,
    sealed: Option<SealedResponse>,
}

/// Lit Chipotle, running the decrypt action's source with a usage key.
pub struct ChipotleReleaser {
    url: String,
    api_key: String,
    code: String,
    agent: ureq::Agent,
}

impl ChipotleReleaser {
    /// A client of the Chipotle API at `url` (for example `https://api.chipotle.litprotocol.com/core/v1/lit_action`) that
    /// runs the action `code` with the usage key `api_key`. The usage key lets its holder run the action; the action
    /// itself decides whether a key is released.
    #[must_use]
    pub fn new(url: &str, api_key: &str, code: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            url: url.to_owned(),
            api_key: api_key.to_owned(),
            code: code.to_owned(),
            agent,
        }
    }
}

impl KeyReleaser for ChipotleReleaser {
    fn release(&self, params: &Value) -> Result<SealedResponse, LitError> {
        let mut response = self
            .agent
            .post(&self.url)
            .header("X-Api-Key", &self.api_key)
            .header("X-Privacy-Mode", "true")
            .send_json(json!({"code": self.code, "js_params": params}))
            .map_err(|_| LitError::Transport)?;
        if response.status().as_u16() != 200 {
            return Err(LitError::Transport);
        }
        let reply: ActionReply = response
            .body_mut()
            .read_json()
            .map_err(|_| LitError::Transport)?;
        let output = reply
            .response
            .filter(|_| !reply.has_error)
            .ok_or(LitError::Transport)?;
        match (output.ok, output.sealed) {
            (true, Some(sealed)) => Ok(sealed),
            (false, None) => Err(LitError::Denied),
            _ => Err(LitError::Transport),
        }
    }
}
