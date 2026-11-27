//! What a job cost, measured by the workload and posted beside its result as a signed object of its own.
//!
//! With the container's stdio off, nothing else can see where a job spent its time. The numbers are wall times per stage,
//! counts, bytes and peak memory; none is derived from the data's content. Every value is an integer of at most 2^53 - 1 and
//! every field name is letters and digits, as the canonical JSON the result key signs requires.

use crate::pipeline::PassTiming;
use crate::store::CipherCache;
use serde_json::{Value, json};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// The version of the metrics object.
pub const METRICS_VERSION: u64 = 1;
/// The most passes the object lists; the passes after the last listed one are added into it.
pub const MAX_PASSES: usize = 16;
/// The largest integer the canonical JSON that is signed can carry: 2^53 - 1.
const MAX_VALUE: u64 = (1 << 53) - 1;

/// A stage of a job whose wall time is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Attesting and claiming the job.
    Claim,
    /// Fetching the job's inputs from the API.
    Job,
    /// Checking the consent, the dataset record on the chain and the manifest.
    Checks,
    /// Having the decrypt action release the key.
    Key,
    /// Making Groth16 proofs.
    Prove,
    /// Signing and posting the result.
    Post,
}

const STAGES: usize = 6;

impl Stage {
    const fn index(self) -> usize {
        match self {
            Self::Claim => 0,
            Self::Job => 1,
            Self::Checks => 2,
            Self::Key => 3,
            Self::Prove => 4,
            Self::Post => 5,
        }
    }
}

#[derive(Default)]
struct Data {
    stages: [Duration; STAGES],
    proofs: u64,
    refreshes: u64,
    passes: Vec<PassTiming>,
}

/// Collects a job's measurements as it runs.
pub struct Recorder {
    started: Instant,
    data: Mutex<Data>,
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or(MAX_VALUE)
        .min(MAX_VALUE)
}

fn capped(value: u64) -> u64 {
    value.min(MAX_VALUE)
}

/// The process's peak resident memory in bytes, from `VmHWM` in `/proc/self/status`; 0 where there is no such file.
#[must_use]
pub fn peak_rss_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| rss_peak_from(&status))
        .unwrap_or(0)
}

/// The `VmHWM` of the text of `/proc/self/status`, in bytes.
#[must_use]
pub fn rss_peak_from(status: &str) -> Option<u64> {
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?;
    let kilobytes: u64 = line.trim().strip_suffix("kB")?.trim().parse().ok()?;
    kilobytes.checked_mul(1024)
}

impl Recorder {
    /// A recorder whose wall clock starts now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            data: Mutex::new(Data::default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Data> {
        self.data.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `work` and adds its wall time to `stage`.
    pub fn time<T>(&self, stage: Stage, work: impl FnOnce() -> T) -> T {
        let began = Instant::now();
        let out = work();
        self.lock().stages[stage.index()] += began.elapsed();
        out
    }

    /// Counts one proof made.
    pub fn proof_made(&self) {
        self.lock().proofs += 1;
    }

    /// Counts one attestation taken after the claim: a sidecar and attestation-service round trip.
    pub fn token_refreshed(&self) {
        self.lock().refreshes += 1;
    }

    /// Adds one pass to the record.
    pub fn record_pass(&self, timing: PassTiming) {
        self.lock().passes.push(timing);
    }

    /// The metrics object as of now, with the fetch figures of `cache`.
    #[must_use]
    pub fn snapshot(&self, cache: &CipherCache) -> Value {
        self.snapshot_with(cache, peak_rss_bytes())
    }

    /// As [`Recorder::snapshot`], with the process's peak memory given.
    #[must_use]
    pub fn snapshot_with(&self, cache: &CipherCache, rss_peak_bytes: u64) -> Value {
        let fetch = cache.fetch_stats();
        let data = self.lock();
        let mut passes: Vec<PassTiming> = data.passes.iter().take(MAX_PASSES).copied().collect();
        if let (Some(last), Some(extras)) = (passes.last_mut(), data.passes.get(MAX_PASSES..)) {
            for extra in extras {
                last.wait += extra.wait;
                last.decrypt += extra.decrypt;
                last.decompress += extra.decompress;
                last.parse += extra.parse;
                last.chunks += extra.chunks;
            }
        }
        let wait: Duration = data.passes.iter().map(|p| p.wait).sum();
        let stage = |s: Stage| millis(data.stages[s.index()]);
        json!({
            "v": METRICS_VERSION,
            "wallMs": millis(self.started.elapsed()),
            "stageMs": {
                "claim": stage(Stage::Claim),
                "job": stage(Stage::Job),
                "checks": stage(Stage::Checks),
                "key": stage(Stage::Key),
                "wait": millis(wait),
                "prove": stage(Stage::Prove),
                "post": stage(Stage::Post),
            },
            "proofs": capped(data.proofs),
            "tokenRefreshes": capped(data.refreshes),
            "fetch": {
                "chunks": capped(fetch.chunks),
                "bytes": capped(fetch.bytes),
                "busyMs": millis(fetch.busy),
                "wallMs": millis(fetch.wall),
            },
            "diskPeakBytes": capped(fetch.disk_bytes),
            "passes": passes.iter().map(|p| json!({
                "decryptMs": millis(p.decrypt),
                "decompressMs": millis(p.decompress),
                "parseMs": millis(p.parse),
                "waitMs": millis(p.wait),
                "chunks": capped(p.chunks),
            })).collect::<Vec<_>>(),
            "rssPeakBytes": capped(rss_peak_bytes),
        })
    }
}
