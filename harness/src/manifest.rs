//! The vault manifest of a dataset: how its plaintext was split, compressed and encrypted.
//!
//! This is `aseryx-hybrid-chipotle-v3`, written by the web application, the Runtime and the CLI. Each chunk of the
//! plaintext is gzipped, encrypted with AES-256-GCM under one dataset key with its own IV, and pinned to IPFS as the
//! ciphertext followed by the 16-byte tag.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

/// The manifest version this workload reads.
pub const MANIFEST_VERSION: &str = "aseryx-hybrid-chipotle-v3";
const MAX_CHUNKS: usize = 4096;
const MAX_CHUNK_BYTES: u64 = 1 << 30;

/// Why a manifest was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    /// The text is not JSON of the manifest's shape.
    #[error("the manifest is not valid: {0}")]
    Shape(String),
    /// A field has a value the format does not allow.
    #[error("the manifest field {0} is not allowed")]
    Field(&'static str),
}

/// One encrypted chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// The content identifier of the ciphertext, without `ipfs://`.
    pub cid: String,
    /// The 12-byte AES-GCM IV.
    pub iv: [u8; 12],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawManifest {
    version: String,
    total_size: u64,
    chunk_size: u64,
    file_type: String,
    plaintext_sha256: String,
    upload_name: String,
    token_id: String,
    dataset: String,
    key_wrap: serde_json::Value,
    action_cid: String,
    chunks: Vec<RawChunk>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawChunk {
    cid: String,
    iv: String,
}

/// A checked manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    /// The plaintext's size in bytes.
    pub total_size: u64,
    /// The plaintext bytes in each chunk but the last.
    pub chunk_size: u64,
    /// The format of the plaintext: `csv`, `json` or `jsonl`.
    pub file_type: String,
    /// The full SHA-256 of the plaintext.
    pub plaintext_sha256: [u8; 32],
    /// The dataset's display name.
    pub upload_name: String,
    /// The Digital Key token id.
    pub token_id: String,
    /// The dataset's registry id.
    pub dataset: String,
    /// The dataset key sealed to the decrypt action, as the manifest carries it.
    pub key_wrap: serde_json::Value,
    /// The content identifier of the decrypt action the key is sealed to.
    pub action_cid: String,
    /// The encrypted chunks, in order.
    pub chunks: Vec<Chunk>,
}

impl Manifest {
    /// Parses and checks a manifest.
    ///
    /// # Errors
    ///
    /// [`ManifestError`] for anything that is not exactly a version 3 manifest: another version, a missing or extra
    /// field, a size that does not fit the chunks, a hash or IV of the wrong shape, or a chunk that is not an `ipfs://`
    /// identifier.
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        let raw: RawManifest = serde_json::from_str(text)
            .map_err(|e| ManifestError::Shape(e.to_string().chars().take(80).collect()))?;
        if raw.version != MANIFEST_VERSION {
            return Err(ManifestError::Field("version"));
        }
        if !matches!(raw.file_type.as_str(), "csv" | "json" | "jsonl") {
            return Err(ManifestError::Field("fileType"));
        }
        if raw.chunk_size == 0 || raw.chunk_size > MAX_CHUNK_BYTES {
            return Err(ManifestError::Field("chunkSize"));
        }
        if raw.chunks.is_empty() || raw.chunks.len() > MAX_CHUNKS {
            return Err(ManifestError::Field("chunks"));
        }
        let expected_chunks = raw.total_size.div_ceil(raw.chunk_size).max(1);
        if u64::try_from(raw.chunks.len()).ok() != Some(expected_chunks) {
            return Err(ManifestError::Field("totalSize"));
        }
        let mut plaintext_sha256 = [0u8; 32];
        hex::decode_to_slice(&raw.plaintext_sha256, &mut plaintext_sha256)
            .map_err(|_| ManifestError::Field("plaintextSha256"))?;
        if raw.plaintext_sha256 != raw.plaintext_sha256.to_ascii_lowercase() {
            return Err(ManifestError::Field("plaintextSha256"));
        }
        let chunks = raw
            .chunks
            .iter()
            .map(parse_chunk)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            total_size: raw.total_size,
            chunk_size: raw.chunk_size,
            file_type: raw.file_type,
            plaintext_sha256,
            upload_name: raw.upload_name,
            token_id: raw.token_id,
            dataset: raw.dataset,
            key_wrap: raw.key_wrap,
            action_cid: raw.action_cid,
            chunks,
        })
    }
}

fn parse_chunk(raw: &RawChunk) -> Result<Chunk, ManifestError> {
    let cid = raw
        .cid
        .strip_prefix("ipfs://")
        .ok_or(ManifestError::Field("chunks.cid"))?;
    if cid.is_empty() || cid.len() > 128 || !cid.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(ManifestError::Field("chunks.cid"));
    }
    let iv: [u8; 12] = STANDARD
        .decode(&raw.iv)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(ManifestError::Field("chunks.iv"))?;
    Ok(Chunk {
        cid: cid.to_owned(),
        iv,
    })
}
