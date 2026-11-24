//! The data label's envelope: the engine's salted label encrypted under a key derived from the dataset key.
//!
//! This is the envelope `labelEnvelope.ts` in the web application writes and opens: `{"v":1,"iv":"<base64>","ct":"<base64>"}`
//! with AES-256-GCM under HKDF-SHA256 of the dataset key (empty salt, info `aseryx/label/v1`) and a random 12-byte IV.
//! Only a holder of the dataset key opens it; the API stores it blind.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;

const LABEL_KEY_INFO: &[u8] = b"aseryx/label/v1";
const IV_BYTES: usize = 12;

/// Why a label could not be sealed or opened.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LabelError {
    /// No random bytes were available for the IV.
    #[error("no random bytes")]
    Random,
    /// The envelope is not of the shape `{"v":1,"iv":"..","ct":".."}`.
    #[error("not a label envelope")]
    Shape,
    /// The envelope does not open under this key, or the label is not UTF-8.
    #[error("the label does not open under this key")]
    Open,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    v: u8,
    iv: String,
    ct: String,
}

fn label_key(dataset_key: &[u8; 32]) -> Aes256Gcm {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, dataset_key)
        .expand(LABEL_KEY_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF output length");
    Aes256Gcm::new(&okm.into())
}

/// The envelope text of `label_json` under the dataset key, with the given IV. Use [`seal_label`] outside tests.
///
/// # Panics
///
/// Never: AES-GCM encryption of a slice cannot fail.
#[must_use]
pub fn seal_label_with_iv(label_json: &str, dataset_key: &[u8; 32], iv: [u8; IV_BYTES]) -> String {
    let ct = label_key(dataset_key)
        .encrypt(&Nonce::from(iv), label_json.as_bytes())
        .expect("AES-GCM encrypts any slice");
    format!(
        r#"{{"v":1,"iv":"{}","ct":"{}"}}"#,
        STANDARD.encode(iv),
        STANDARD.encode(ct)
    )
}

/// The envelope text of `label_json` under the dataset key, with a fresh random IV.
///
/// # Errors
///
/// [`LabelError::Random`] if no random bytes are available.
pub fn seal_label(label_json: &str, dataset_key: &[u8; 32]) -> Result<String, LabelError> {
    let mut iv = [0u8; IV_BYTES];
    getrandom::fill(&mut iv).map_err(|_| LabelError::Random)?;
    Ok(seal_label_with_iv(label_json, dataset_key, iv))
}

/// The label's JSON text from its envelope.
///
/// # Errors
///
/// [`LabelError::Shape`] for another shape and [`LabelError::Open`] for another key or a changed ciphertext.
pub fn open_label(envelope: &str, dataset_key: &[u8; 32]) -> Result<String, LabelError> {
    let parsed: Envelope = serde_json::from_str(envelope).map_err(|_| LabelError::Shape)?;
    let iv: [u8; IV_BYTES] = STANDARD
        .decode(&parsed.iv)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(LabelError::Shape)?;
    let ct = STANDARD.decode(&parsed.ct).map_err(|_| LabelError::Shape)?;
    if parsed.v != 1 || ct.len() < 16 {
        return Err(LabelError::Shape);
    }
    let plain = label_key(dataset_key)
        .decrypt(&Nonce::from(iv), ct.as_slice())
        .map_err(|_| LabelError::Open)?;
    String::from_utf8(plain).map_err(|_| LabelError::Open)
}
