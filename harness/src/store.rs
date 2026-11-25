//! The encrypted chunks of a dataset: fetched from IPFS once, kept on disk as ciphertext, read again for every pass.
//!
//! Only ciphertext reaches the disk. The chunks are public on IPFS, so storing them protects nothing that is not already
//! public; the plaintext exists only in memory.

use crate::manifest::Chunk;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

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
    /// The disk has less room than the dataset's ciphertext and the workload's own files need.
    #[error("the disk has no room for the dataset")]
    NoRoom,
}

/// Disk the workload keeps for its own files next to the ciphertext: the circuit artifacts, the proof and the label.
pub const DISK_RESERVE_BYTES: u64 = 2 << 30;

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

/// The free bytes on the disk that holds a directory, as an unprivileged process can use them.
fn free_bytes(dir: &Path) -> io::Result<u64> {
    let stat = rustix::fs::statvfs(dir)?;
    Ok(stat.f_bavail.saturating_mul(stat.f_frsize))
}

/// Reads how many bytes are free on the disk holding a directory.
type FreeSpace = Box<dyn Fn(&Path) -> io::Result<u64> + Send + Sync>;

/// Why fetching stopped, kept so every reader that waits can be told.
#[derive(Debug, Clone, Copy)]
enum Failure {
    Fetch,
    TooShort,
    Cache,
}

impl From<&StoreError> for Failure {
    fn from(error: &StoreError) -> Self {
        match error {
            StoreError::TooShort => Self::TooShort,
            StoreError::Cache(_) | StoreError::NoRoom => Self::Cache,
            StoreError::Fetch => Self::Fetch,
        }
    }
}

impl From<Failure> for StoreError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Fetch => Self::Fetch,
            Failure::TooShort => Self::TooShort,
            Failure::Cache => Self::Cache(io::Error::other("the chunk cache failed")),
        }
    }
}

/// What fetching the chunks cost: nothing derived from their content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FetchStats {
    /// Chunks that are on disk, fetched or already cached.
    pub chunks: u64,
    /// Bytes downloaded.
    pub bytes: u64,
    /// Bytes of ciphertext on disk, downloaded or already there.
    pub disk_bytes: u64,
    /// The time the fetch threads spent fetching, added up over the threads.
    pub busy: Duration,
    /// The time from the first fetch to the last chunk landing.
    pub wall: Duration,
}

/// What one chunk's fetch left on disk.
struct Fetched {
    downloaded: u64,
    on_disk: u64,
}

#[derive(Default)]
struct Progress {
    landed: HashSet<String>,
    failure: Option<Failure>,
    workers: usize,
    cancelled: bool,
    started: Option<Instant>,
    ended: Option<Instant>,
    stats: FetchStats,
}

/// A directory of ciphertext chunks, one file per content identifier.
///
/// Chunks are fetched by threads that run while the job does other work, and a reader asks for a chunk by name and waits
/// until it has landed ([`CipherCache::read_waiting`]), so the passes parse the first chunks while the later ones download.
pub struct CipherCache {
    dir: PathBuf,
    free_bytes: FreeSpace,
    next: AtomicUsize,
    progress: Mutex<Progress>,
    arrived: Condvar,
}

impl CipherCache {
    /// A cache in `dir`, which is created when missing.
    ///
    /// # Errors
    ///
    /// [`StoreError::Cache`] if the directory cannot be created.
    pub fn new(dir: &Path) -> Result<Self, StoreError> {
        Self::with_free_space(dir, free_bytes)
    }

    /// A cache in `dir` that asks `free_bytes` how much room the disk holding it has, for tests that need a full disk.
    ///
    /// # Errors
    ///
    /// [`StoreError::Cache`] if the directory cannot be created.
    pub fn with_free_space(
        dir: &Path,
        free_bytes: impl Fn(&Path) -> io::Result<u64> + Send + Sync + 'static,
    ) -> Result<Self, StoreError> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_owned(),
            free_bytes: Box::new(free_bytes),
            next: AtomicUsize::new(0),
            progress: Mutex::new(Progress::default()),
            arrived: Condvar::new(),
        })
    }

    /// Checks, before anything is fetched, that the disk can hold every chunk at its largest (`max_chunk_bytes`, see
    /// [`chunk_limit`]) and [`DISK_RESERVE_BYTES`] besides.
    ///
    /// # Errors
    ///
    /// [`StoreError::NoRoom`] when it cannot; [`StoreError::Cache`] when the free space cannot be read.
    pub fn ensure_room(&self, chunk_count: usize, max_chunk_bytes: u64) -> Result<(), StoreError> {
        let needed = (chunk_count as u64)
            .saturating_mul(max_chunk_bytes)
            .saturating_add(DISK_RESERVE_BYTES);
        if (self.free_bytes)(&self.dir)? < needed {
            return Err(StoreError::NoRoom);
        }
        Ok(())
    }

    fn path(&self, cid: &str) -> PathBuf {
        self.dir.join(cid)
    }

    fn lock(&self) -> MutexGuard<'_, Progress> {
        self.progress.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts `parallel` threads in `scope` that fetch every chunk that is not cached yet, in order, and returns at once.
    /// Each chunk is written to disk under a temporary name before it takes its final one; a chunk longer than `max_bytes`
    /// is refused (see [`chunk_limit`]). The first failure stops the threads and every reader that waits gets it. The
    /// scope ends when the threads have, so a caller that no longer needs the chunks calls [`CipherCache::cancel`] first.
    pub fn start_fetching<'scope, 'env: 'scope>(
        &'env self,
        scope: &'scope std::thread::Scope<'scope, 'env>,
        chunks: &'env [Chunk],
        fetcher: &'env dyn Fetcher,
        parallel: usize,
        max_bytes: u64,
    ) {
        let workers = parallel.clamp(1, chunks.len().max(1));
        self.next.store(0, Ordering::Relaxed);
        *self.lock() = Progress {
            workers,
            started: Some(Instant::now()),
            ..Progress::default()
        };
        for _ in 0..workers {
            scope.spawn(move || self.work(chunks, fetcher, max_bytes));
        }
    }

    fn work(&self, chunks: &[Chunk], fetcher: &dyn Fetcher, max_bytes: u64) {
        loop {
            {
                let progress = self.lock();
                if progress.cancelled || progress.failure.is_some() {
                    break;
                }
            }
            let Some(chunk) = chunks.get(self.next.fetch_add(1, Ordering::Relaxed)) else {
                break;
            };
            let began = Instant::now();
            let outcome = self.fetch_one(chunk, fetcher, max_bytes);
            let mut progress = self.lock();
            progress.stats.busy += began.elapsed();
            match outcome {
                Ok(fetched) => {
                    progress.landed.insert(chunk.cid.clone());
                    progress.stats.chunks += 1;
                    progress.stats.bytes += fetched.downloaded;
                    progress.stats.disk_bytes += fetched.on_disk;
                    progress.ended = Some(Instant::now());
                }
                Err(error) => {
                    progress.failure.get_or_insert(Failure::from(&error));
                }
            }
            self.arrived.notify_all();
        }
        let mut progress = self.lock();
        progress.workers = progress.workers.saturating_sub(1);
        self.arrived.notify_all();
    }

    /// Stops the fetch threads after the chunks they are fetching now, and wakes every reader that waits.
    pub fn cancel(&self) {
        self.lock().cancelled = true;
        self.arrived.notify_all();
    }

    /// What fetching has cost so far.
    #[must_use]
    pub fn fetch_stats(&self) -> FetchStats {
        let progress = self.lock();
        let mut stats = progress.stats;
        if let (Some(started), Some(ended)) = (progress.started, progress.ended) {
            stats.wall = ended.saturating_duration_since(started);
        }
        stats
    }

    /// Fetches every chunk that is not cached yet, with at most `parallel` fetches in flight, and returns when they have
    /// landed (see [`CipherCache::start_fetching`]).
    ///
    /// # Errors
    ///
    /// The first failure any fetch or write raised. Chunks fetched before it stay cached.
    pub fn fill(
        &self,
        chunks: &[Chunk],
        fetcher: &dyn Fetcher,
        parallel: usize,
        max_bytes: u64,
    ) -> Result<(), StoreError> {
        std::thread::scope(|scope| {
            self.start_fetching(scope, chunks, fetcher, parallel, max_bytes)
        });
        match self.lock().failure {
            Some(failure) => Err(failure.into()),
            None => Ok(()),
        }
    }

    fn fetch_one(
        &self,
        chunk: &Chunk,
        fetcher: &dyn Fetcher,
        max_bytes: u64,
    ) -> Result<Fetched, StoreError> {
        let path = self.path(&chunk.cid);
        if let Some(length) = fs::metadata(&path)
            .ok()
            .map(|m| m.len())
            .filter(|length| *length >= MIN_CIPHERTEXT_BYTES as u64)
        {
            return Ok(Fetched {
                downloaded: 0,
                on_disk: length,
            });
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
        let length = bytes.len() as u64;
        Ok(Fetched {
            downloaded: length,
            on_disk: length,
        })
    }

    /// The ciphertext of a chunk, once it has landed, and how long the call waited for it. Without fetch threads running
    /// it reads what is on disk.
    ///
    /// # Errors
    ///
    /// The failure that stopped the fetch threads, or [`StoreError::Cache`] when the chunk is not on disk and nothing is
    /// fetching it, or [`StoreError::TooShort`] if it is shorter than a tag.
    pub fn read_waiting(&self, cid: &str) -> Result<(Vec<u8>, Duration), StoreError> {
        let began = Instant::now();
        let mut progress = self.lock();
        loop {
            if progress.landed.contains(cid) {
                break;
            }
            if let Some(failure) = progress.failure {
                return Err(failure.into());
            }
            if progress.workers == 0 || progress.cancelled {
                break;
            }
            progress = self
                .arrived
                .wait(progress)
                .unwrap_or_else(PoisonError::into_inner);
        }
        drop(progress);
        let waited = began.elapsed();
        self.read(cid).map(|bytes| (bytes, waited))
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
