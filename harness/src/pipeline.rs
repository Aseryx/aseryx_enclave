//! Reading a dataset's chunks through the engine: decrypt, decompress, feed, and check the hash of every pass.
//!
//! The engine reads the file more than once. Each pass decrypts the cached chunks in order and streams the plaintext to
//! the engine in slices, so no full copy of the plaintext exists. After each pass the SHA-256 of what was fed must equal
//! the registered plaintext hash.

use crate::engine::{EngineError, Run};
use crate::error_code::ErrorCode;
use crate::manifest::{Chunk, Manifest};
use crate::metrics::Recorder;
use crate::store::{CipherCache, StoreError};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::{Duration, Instant};

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

/// Where one pass spent its time, and nothing derived from the data's content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PassTiming {
    /// Time blocked on a chunk that had not landed yet.
    pub wait: Duration,
    /// Time in AES-GCM decryption.
    pub decrypt: Duration,
    /// Time in gunzip.
    pub decompress: Duration,
    /// Time hashing the plaintext and feeding it to the engines.
    pub parse: Duration,
    /// Chunks read.
    pub chunks: u64,
}

/// Decrypts one chunk (ciphertext followed by its 16-byte tag) and streams its gunzipped plaintext to `sink`, returning
/// the number of plaintext bytes. The time spent is added to `timing`.
fn stream_chunk(
    key: &[u8; 32],
    chunk: &Chunk,
    sealed: &[u8],
    timing: &mut PassTiming,
    sink: &mut dyn FnMut(&[u8]) -> Result<(), PipelineError>,
) -> Result<u64, PipelineError> {
    let cipher = Aes256Gcm::new(key.into());
    let began = Instant::now();
    let compressed = cipher
        .decrypt(&Nonce::from(chunk.iv), sealed)
        .map_err(|_| PipelineError::Chunk)?;
    timing.decrypt += began.elapsed();
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut buffer = vec![0u8; FEED_SLICE_BYTES];
    let mut total = 0u64;
    loop {
        let began = Instant::now();
        let n = decoder
            .read(&mut buffer)
            .map_err(|_| PipelineError::Chunk)?;
        timing.decompress += began.elapsed();
        if n == 0 {
            return Ok(total);
        }
        let began = Instant::now();
        sink(&buffer[..n])?;
        timing.parse += began.elapsed();
        total += n as u64;
    }
}

/// Feeds the whole dataset to every run once and returns the SHA-256 of the plaintext it fed. `timing` holds where the pass
/// spent its time, up to the failure when there is one.
fn feed_pass(
    runs: &mut [Run],
    manifest: &Manifest,
    key: &[u8; 32],
    cache: &CipherCache,
    timing: &mut PassTiming,
) -> Result<[u8; 32], PipelineError> {
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    for chunk in &manifest.chunks {
        let (sealed, waited) = cache.read_waiting(&chunk.cid)?;
        timing.wait += waited;
        timing.chunks += 1;
        total += stream_chunk(key, chunk, &sealed, timing, &mut |slice| {
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
    runs: Vec<Run>,
    manifest: &Manifest,
    key: &[u8; 32],
    cache: &CipherCache,
    expected: &[u8; 32],
) -> Result<Vec<String>, PipelineError> {
    run_passes_many_recorded(runs, manifest, key, cache, expected, &Recorder::new())
}

/// As [`run_passes_many`], and records each pass's timing in `recorder` as the pass ends, so a
/// pass that fails is in the record up to its failure.
///
/// # Errors
///
/// As [`run_passes_many`].
pub fn run_passes_many_recorded(
    mut runs: Vec<Run>,
    manifest: &Manifest,
    key: &[u8; 32],
    cache: &CipherCache,
    expected: &[u8; 32],
    recorder: &Recorder,
) -> Result<Vec<String>, PipelineError> {
    loop {
        let mut timing = PassTiming::default();
        let fed = feed_pass(&mut runs, manifest, key, cache, &mut timing);
        recorder.record_pass(timing);
        if fed? != *expected {
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
    run_passes_recorded(run, manifest, key, cache, expected, &Recorder::new())
}

/// As [`run_passes`], recording as [`run_passes_many_recorded`] does.
///
/// # Errors
///
/// As [`run_passes_many`].
pub fn run_passes_recorded(
    run: Run,
    manifest: &Manifest,
    key: &[u8; 32],
    cache: &CipherCache,
    expected: &[u8; 32],
    recorder: &Recorder,
) -> Result<String, PipelineError> {
    let mut results =
        run_passes_many_recorded(vec![run], manifest, key, cache, expected, recorder)?;
    Ok(results.remove(0))
}
