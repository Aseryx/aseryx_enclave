//! Reading a dataset's chunks through the engine: decrypt, decompress, feed, and check the hash of every pass.
//!
//! The engine reads the file more than once. Each pass decrypts the cached chunks in order and streams the plaintext to
//! the engine in slices, so no full copy of the plaintext exists. After each pass the SHA-256 of what was fed must equal
//! the registered plaintext hash.

use crate::engine::{EngineError, Run};
use crate::error_code::ErrorCode;
use crate::manifest::{Chunk, Manifest};
use crate::store::{CipherCache, StoreError};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::io::Read;

const FEED_SLICE_BYTES: usize = 1 << 20;

/// Why a pass over the dataset failed.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// A chunk could not be read from the cache.
    #[error("a chunk could not be read: {0}")]
    Store(#[from] StoreError),
    /// A chunk does not authenticate under the dataset key, or does not decompress.
    #[error("a chunk is not valid ciphertext of this dataset")]
    Chunk,
    /// The plaintext is not the size the manifest records.
    #[error("the plaintext has another size than the manifest records")]
    Size,
    /// The plaintext does not hash to the registered hash.
    #[error("the plaintext does not hash to the registered hash")]
    HashMismatch,
    /// The engine failed.
    #[error("the engine failed: {0}")]
    Engine(#[from] EngineError),
}

impl PipelineError {
    /// The code a workload reports for this failure.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Store(_) => ErrorCode::FetchFailed,
            Self::Chunk | Self::Size | Self::HashMismatch => ErrorCode::HashMismatch,
            Self::Engine(_) => ErrorCode::AppraiseFailed,
        }
    }
}

/// Decrypts one chunk (ciphertext followed by its 16-byte tag) and streams its gunzipped plaintext to `sink`, returning
/// the number of plaintext bytes.
fn stream_chunk(
    key: &[u8; 32],
    chunk: &Chunk,
    sealed: &[u8],
    sink: &mut dyn FnMut(&[u8]) -> Result<(), PipelineError>,
) -> Result<u64, PipelineError> {
    let cipher = Aes256Gcm::new(key.into());
    let compressed = cipher
        .decrypt(&Nonce::from(chunk.iv), sealed)
        .map_err(|_| PipelineError::Chunk)?;
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut buffer = vec![0u8; FEED_SLICE_BYTES];
    let mut total = 0u64;
    loop {
        let n = decoder
            .read(&mut buffer)
            .map_err(|_| PipelineError::Chunk)?;
        if n == 0 {
            return Ok(total);
        }
        sink(&buffer[..n])?;
        total += n as u64;
    }
}

/// Feeds the whole dataset to every run once and returns the SHA-256 of the plaintext it fed.
fn feed_pass(
    runs: &mut [Run],
    manifest: &Manifest,
    key: &[u8; 32],
    cache: &CipherCache,
) -> Result<[u8; 32], PipelineError> {
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    for chunk in &manifest.chunks {
        let (sealed, _waited) = cache.read_waiting(&chunk.cid)?;
        total += stream_chunk(key, chunk, &sealed, &mut |slice| {
            hasher.update(slice);
            runs.iter_mut()
                .try_for_each(|run| run.feed(slice))
                .map_err(PipelineError::from)
        })?;
    }
    if total != manifest.total_size {
        return Err(PipelineError::Size);
    }
    Ok(hasher.finalize().into())
}

/// Runs every pass the engines ask for over the cached chunks and returns each engine's JSON result, in the order of
/// `runs`. The runs share the passes, so several checks over one file decrypt it only as often as one.
///
/// `expected` is the plaintext hash from the chain registry; every pass must hash to it.
///
/// # Errors
///
/// [`PipelineError`]: a chunk that is missing, tampered with or the wrong size, a pass that does not hash to `expected`,
/// an engine failure, or runs that ask for different numbers of passes.
pub fn run_passes_many(
    mut runs: Vec<Run>,
    manifest: &Manifest,
    key: &[u8; 32],
    cache: &CipherCache,
    expected: &[u8; 32],
) -> Result<Vec<String>, PipelineError> {
    loop {
        if feed_pass(&mut runs, manifest, key, cache)? != *expected {
            return Err(PipelineError::HashMismatch);
        }
        let more = runs
            .iter_mut()
            .map(Run::next_pass)
            .collect::<Result<Vec<_>, _>>()?;
        if more.iter().any(|m| *m != more[0]) {
            return Err(PipelineError::Engine(EngineError::Module(
                "the engine asked for different passes".to_owned(),
            )));
        }
        if !more.first().copied().unwrap_or(false) {
            return Ok(runs
                .into_iter()
                .map(Run::finish)
                .collect::<Result<_, _>>()?);
        }
    }
}

/// Runs every pass the engine asks for over the cached chunks and returns the engine's JSON result.
///
/// # Errors
///
/// As [`run_passes_many`].
pub fn run_passes(
    run: Run,
    manifest: &Manifest,
    key: &[u8; 32],
    cache: &CipherCache,
    expected: &[u8; 32],
) -> Result<String, PipelineError> {
    let mut results = run_passes_many(vec![run], manifest, key, cache, expected)?;
    Ok(results.remove(0))
}
