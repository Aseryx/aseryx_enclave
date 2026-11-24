//! The encrypted chunks of a dataset: fetched from IPFS once, kept on disk as ciphertext, read again for every pass.
//!
//! Only ciphertext reaches the disk. The chunks are public on IPFS, so storing them protects nothing that is not already
//! public; the plaintext exists only in memory.

use crate::manifest::Chunk;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const GATEWAY_TIMEOUT: Duration = Duration::from_secs(300);
const MIN_CIPHERTEXT_BYTES: usize = 16;

/// Why a chunk could not be fetched or read.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The gateway could not be reached or answered with an error status.
    #[error("a chunk could not be fetched")]
    Fetch,
    /// A chunk is shorter than an AES-GCM tag.
    #[error("a chunk is too short to be ciphertext")]
    TooShort,
    /// The cache directory could not be written or read.
    #[error("the chunk cache failed: {0}")]
    Cache(#[from] io::Error),
}

/// Something that can fetch a chunk's ciphertext by its content identifier.
pub trait Fetcher: Sync {
    /// The bytes pinned under `cid`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Fetch`] if they could not be fetched.
    fn fetch(&self, cid: &str) -> Result<Vec<u8>, StoreError>;
}

/// An IPFS HTTP gateway.
pub struct IpfsGateway {
    base_url: String,
    agent: ureq::Agent,
}

impl IpfsGateway {
    /// A client of the gateway at `base_url`, which serves `GET <base_url>/ipfs/<cid>`.
    #[must_use]
    pub fn new(base_url: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(GATEWAY_TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            agent,
        }
    }
}

impl Fetcher for IpfsGateway {
    fn fetch(&self, cid: &str) -> Result<Vec<u8>, StoreError> {
        let mut response = self
            .agent
            .get(format!("{}/ipfs/{cid}", self.base_url))
            .call()
            .map_err(|_| StoreError::Fetch)?;
        if response.status().as_u16() != 200 {
            return Err(StoreError::Fetch);
        }
        response
            .body_mut()
            .with_config()
            .limit(u64::MAX)
            .read_to_vec()
            .map_err(|_| StoreError::Fetch)
    }
}

/// A directory of ciphertext chunks, one file per content identifier.
pub struct CipherCache {
    dir: PathBuf,
}

impl CipherCache {
    /// A cache in `dir`, which is created when missing.
    ///
    /// # Errors
    ///
    /// [`StoreError::Cache`] if the directory cannot be created.
    pub fn new(dir: &Path) -> Result<Self, StoreError> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_owned(),
        })
    }

    fn path(&self, cid: &str) -> PathBuf {
        self.dir.join(cid)
    }

    /// Fetches every chunk that is not cached yet, with at most `parallel` fetches in flight, and writes each to disk
    /// under a temporary name before it takes its final one.
    ///
    /// # Errors
    ///
    /// The first [`StoreError`] any fetch or write raised. Chunks fetched before it stay cached.
    pub fn fill(
        &self,
        chunks: &[Chunk],
        fetcher: &dyn Fetcher,
        parallel: usize,
    ) -> Result<(), StoreError> {
        let next = AtomicUsize::new(0);
        let failure = std::sync::Mutex::new(None::<StoreError>);
        std::thread::scope(|scope| {
            for _ in 0..parallel.clamp(1, chunks.len().max(1)) {
                scope.spawn(|| {
                    while failure.lock().map_or(true, |f| f.is_none()) {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(chunk) = chunks.get(index) else {
                            return;
                        };
                        if let Err(error) = self.fetch_one(chunk, fetcher) {
                            if let Ok(mut slot) = failure.lock() {
                                slot.get_or_insert(error);
                            }
                            return;
                        }
                    }
                });
            }
        });
        match failure.into_inner().ok().flatten() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn fetch_one(&self, chunk: &Chunk, fetcher: &dyn Fetcher) -> Result<(), StoreError> {
        let path = self.path(&chunk.cid);
        if fs::metadata(&path).is_ok_and(|m| m.len() >= MIN_CIPHERTEXT_BYTES as u64) {
            return Ok(());
        }
        let bytes = fetcher.fetch(&chunk.cid)?;
        if bytes.len() < MIN_CIPHERTEXT_BYTES {
            return Err(StoreError::TooShort);
        }
        let temporary = self.dir.join(format!("{}.part", chunk.cid));
        let mut file = fs::File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        Ok(())
    }

    /// The ciphertext of a cached chunk.
    ///
    /// # Errors
    ///
    /// [`StoreError::Cache`] if the chunk was not cached, [`StoreError::TooShort`] if it is shorter than a tag.
    pub fn read(&self, cid: &str) -> Result<Vec<u8>, StoreError> {
        let bytes = fs::read(self.path(cid))?;
        if bytes.len() < MIN_CIPHERTEXT_BYTES {
            return Err(StoreError::TooShort);
        }
        Ok(bytes)
    }
}
