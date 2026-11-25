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

/// The most a chunk of `chunk_size` plaintext bytes can weigh as stored: gzip of data that does not compress adds a few
/// bytes per block and a header, and AES-GCM adds a 16-byte tag. The limit leaves a generous margin and still stops a
/// source that streams without end.
#[must_use]
pub const fn chunk_limit(chunk_size: u64) -> u64 {
    chunk_size + chunk_size / 16 + 4096
}

/// The most a manifest may weigh.
pub const MAX_MANIFEST_BYTES: u64 = 4 << 20;

/// Something that can fetch a chunk's ciphertext by its content identifier.
pub trait Fetcher: Sync {
    /// The bytes pinned under `cid`, at most `max_bytes` of them.
    ///
    /// # Errors
    ///
    /// [`StoreError::Fetch`] if they could not be fetched or are longer than `max_bytes`.
    fn fetch(&self, cid: &str, max_bytes: u64) -> Result<Vec<u8>, StoreError>;
}

/// IPFS HTTP gateways, tried in order.
///
/// A chunk is authenticated by AES-GCM and the plaintext by its registered hash, so a gateway that answers wrongly cannot
/// pass anything off: the first gateway that answers is taken, and an unreachable, failing or over-long answer falls
/// through to the next.
pub struct IpfsGateway {
    base_urls: Vec<String>,
    agent: ureq::Agent,
}

impl IpfsGateway {
    /// A client of the gateways at `base_urls`, each of which serves `GET <base_url>/ipfs/<cid>`.
    #[must_use]
    pub fn new(base_urls: &[&str]) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(GATEWAY_TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            base_urls: base_urls
                .iter()
                .map(|url| url.trim_end_matches('/').to_owned())
                .collect(),
            agent,
        }
    }

    fn fetch_from(&self, base_url: &str, cid: &str, max_bytes: u64) -> Result<Vec<u8>, StoreError> {
        let mut response = self
            .agent
            .get(format!("{base_url}/ipfs/{cid}"))
            .call()
            .map_err(|_| StoreError::Fetch)?;
        if response.status().as_u16() != 200 {
            return Err(StoreError::Fetch);
        }
        response
            .body_mut()
            .with_config()
            .limit(max_bytes)
            .read_to_vec()
            .map_err(|_| StoreError::Fetch)
    }
}

impl Fetcher for IpfsGateway {
    fn fetch(&self, cid: &str, max_bytes: u64) -> Result<Vec<u8>, StoreError> {
        self.base_urls
            .iter()
            .find_map(|base_url| self.fetch_from(base_url, cid, max_bytes).ok())
            .ok_or(StoreError::Fetch)
    }
}

/// Something that can fetch a URL the API signed, up to a size.
pub trait UrlFetcher: Sync {
    /// The body of `url`, at most `max_bytes` long.
    ///
    /// # Errors
    ///
    /// [`StoreError::Fetch`] if the URL is refused, unreachable, answers an error status or has a longer body.
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, StoreError>;
}

/// Fetches signed URLs over HTTPS, and nothing else.
pub struct HttpFetcher {
    agent: ureq::Agent,
}

impl HttpFetcher {
    /// A fetcher with the gateway's timeout.
    #[must_use]
    pub fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(GATEWAY_TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .build()
            .into();
        Self { agent }
    }
}

impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl UrlFetcher for HttpFetcher {
    fn get(&self, url: &str, max_bytes: u64) -> Result<Vec<u8>, StoreError> {
        if !url.starts_with("https://") {
            return Err(StoreError::Fetch);
        }
        let mut response = self.agent.get(url).call().map_err(|_| StoreError::Fetch)?;
        if response.status().as_u16() != 200 {
            return Err(StoreError::Fetch);
        }
        response
            .body_mut()
            .with_config()
            .limit(max_bytes)
            .read_to_vec()
            .map_err(|_| StoreError::Fetch)
    }
}

/// Chunks fetched from signed URLs: each chunk identifier of a manifest is served by the URL at the same position.
pub struct UrlChunks<'a> {
    urls: std::collections::HashMap<String, String>,
    fetcher: &'a dyn UrlFetcher,
}

impl<'a> UrlChunks<'a> {
    /// Chunks `chunks` served by `urls`, in order.
    ///
    /// # Errors
    ///
    /// [`StoreError::Fetch`] if the lists differ in length or a chunk identifier repeats.
    pub fn new(
        chunks: &[Chunk],
        urls: &[String],
        fetcher: &'a dyn UrlFetcher,
    ) -> Result<Self, StoreError> {
        if chunks.len() != urls.len() {
            return Err(StoreError::Fetch);
        }
        let mut map = std::collections::HashMap::new();
        for (chunk, url) in chunks.iter().zip(urls) {
            if map.insert(chunk.cid.clone(), url.clone()).is_some() {
                return Err(StoreError::Fetch);
            }
        }
        Ok(Self { urls: map, fetcher })
    }
}

impl Fetcher for UrlChunks<'_> {
    fn fetch(&self, cid: &str, max_bytes: u64) -> Result<Vec<u8>, StoreError> {
        let url = self.urls.get(cid).ok_or(StoreError::Fetch)?;
        self.fetcher.get(url, max_bytes)
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
    /// under a temporary name before it takes its final one. A chunk longer than `max_bytes` is refused: see
    /// [`chunk_limit`].
    ///
    /// # Errors
    ///
    /// The first [`StoreError`] any fetch or write raised. Chunks fetched before it stay cached.
    pub fn fill(
        &self,
        chunks: &[Chunk],
        fetcher: &dyn Fetcher,
        parallel: usize,
        max_bytes: u64,
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
                        if let Err(error) = self.fetch_one(chunk, fetcher, max_bytes) {
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

    fn fetch_one(
        &self,
        chunk: &Chunk,
        fetcher: &dyn Fetcher,
        max_bytes: u64,
    ) -> Result<(), StoreError> {
        let path = self.path(&chunk.cid);
        if fs::metadata(&path).is_ok_and(|m| m.len() >= MIN_CIPHERTEXT_BYTES as u64) {
            return Ok(());
        }
        let bytes = fetcher.fetch(&chunk.cid, max_bytes)?;
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
