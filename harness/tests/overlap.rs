//! The cache hands out a chunk as soon as it has landed, makes a reader wait for one that has not, and wakes every reader
//! when the fetching fails or is cancelled.

mod common;

use aseryx_enclave_harness::manifest::Chunk;
use aseryx_enclave_harness::store::{CipherCache, Fetcher, StoreError};
use common::unique_dir;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Mutex, mpsc};
use std::time::Duration;

fn chunks(count: usize) -> Vec<Chunk> {
    (0..count)
        .map(|i| Chunk {
            cid: format!("QmC{i}"),
            iv: [i as u8; 12],
        })
        .collect()
}

/// Serves 32-byte chunks; the fetch of a held chunk blocks until the test releases it, and a chunk named in `failing`
/// is an error.
struct Gated {
    held: Mutex<HashMap<String, Receiver<()>>>,
    failing: Vec<String>,
}

impl Fetcher for Gated {
    fn fetch(&self, cid: &str, _: u64) -> Result<Vec<u8>, StoreError> {
        let gate = self.held.lock().expect("lock").remove(cid);
        if let Some(gate) = gate {
            let _ = gate.recv();
        }
        if self.failing.iter().any(|f| f == cid) {
            return Err(StoreError::Fetch);
        }
        Ok(cid.as_bytes().iter().cycle().take(32).copied().collect())
    }
}

/// Releases every held fetch when it is dropped, so a test that fails does not leave a fetch thread blocked.
struct ReleaseOnDrop<'a>(&'a HashMap<String, mpsc::Sender<()>>);

impl Drop for ReleaseOnDrop<'_> {
    fn drop(&mut self) {
        for gate in self.0.values() {
            let _ = gate.send(());
        }
    }
}

fn gated(held: &[&str], failing: &[&str]) -> (Gated, HashMap<String, mpsc::Sender<()>>) {
    let mut gates = HashMap::new();
    let mut receivers = HashMap::new();
    for cid in held {
        let (tx, rx) = channel();
        gates.insert((*cid).to_owned(), tx);
        receivers.insert((*cid).to_owned(), rx);
    }
    (
        Gated {
            held: Mutex::new(receivers),
            failing: failing.iter().map(|s| (*s).to_owned()).collect(),
        },
        gates,
    )
}

/// A chunk that has landed is read at once, and a reader of one that has not waits for it and is told how long it waited.
#[test]
fn a_reader_waits_for_a_chunk_that_has_not_landed() {
    let list = chunks(3);
    let (fetcher, gates) = gated(&["QmC1"], &[]);
    let cache = CipherCache::new(&unique_dir("overlap-wait")).expect("cache");
    let finished = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let _release = ReleaseOnDrop(&gates);
        cache.start_fetching(scope, &list, &fetcher, 1, u64::MAX);
        let (first, _) = cache.read_waiting("QmC0").expect("first chunk");
        assert_eq!(first.len(), 32);
        let reader = scope.spawn(|| {
            let out = cache.read_waiting("QmC1");
            finished.store(true, Ordering::SeqCst);
            out
        });
        std::thread::sleep(Duration::from_millis(60));
        let returned_early = finished.load(Ordering::SeqCst);
        // Released before any assertion, so a failure does not leave the fetch thread blocked
        gates["QmC1"].send(()).expect("release");
        assert!(
            !returned_early,
            "the reader returned before the chunk landed"
        );
        let (bytes, waited) = reader.join().expect("reader").expect("second chunk");
        assert_eq!(bytes.len(), 32);
        assert!(waited >= Duration::from_millis(50), "waited {waited:?}");
        let (third, _) = cache.read_waiting("QmC2").expect("third chunk");
        assert_eq!(third.len(), 32);
    });
    let stats = cache.fetch_stats();
    assert_eq!((stats.chunks, stats.bytes, stats.disk_bytes), (3, 96, 96));
}

/// A chunk that never arrives fails every reader waiting for it, with the failure of the fetch, instead of leaving them
/// waiting; the chunks that did land stay readable.
#[test]
fn a_failed_fetch_wakes_the_readers_with_its_failure() {
    let list = chunks(3);
    let (fetcher, gates) = gated(&["QmC1"], &["QmC1"]);
    let cache = CipherCache::new(&unique_dir("overlap-fail")).expect("cache");
    std::thread::scope(|scope| {
        let _release = ReleaseOnDrop(&gates);
        cache.start_fetching(scope, &list, &fetcher, 1, u64::MAX);
        let reader = scope.spawn(|| cache.read_waiting("QmC1"));
        gates["QmC1"].send(()).expect("release");
        assert!(matches!(
            reader.join().expect("reader"),
            Err(StoreError::Fetch)
        ));
        assert!(cache.read_waiting("QmC0").is_ok());
        assert!(matches!(cache.read_waiting("QmC2"), Err(StoreError::Fetch)));
    });
}

/// Cancelling the fetch wakes a reader that waits for a chunk that was never fetched, and that reader gets the missing
/// file's error.
#[test]
fn cancelling_wakes_a_waiting_reader() {
    let list = chunks(2);
    let (fetcher, gates) = gated(&["QmC1"], &[]);
    let cache = CipherCache::new(&unique_dir("overlap-cancel")).expect("cache");
    std::thread::scope(|scope| {
        let _release = ReleaseOnDrop(&gates);
        cache.start_fetching(scope, &list, &fetcher, 1, u64::MAX);
        let reader = scope.spawn(|| cache.read_waiting("QmC1"));
        std::thread::sleep(Duration::from_millis(30));
        cache.cancel();
        let outcome = reader.join().expect("reader");
        gates["QmC1"].send(()).expect("release the fetch thread");
        assert!(matches!(outcome, Err(StoreError::Cache(_))));
    });
}

/// With nothing fetching, a chunk on disk is read and a missing one is an error, so a cache filled earlier needs no threads.
#[test]
fn a_filled_cache_is_read_without_threads() {
    let list = chunks(2);
    let (fetcher, _gates) = gated(&[], &[]);
    let cache = CipherCache::new(&unique_dir("overlap-filled")).expect("cache");
    cache.fill(&list, &fetcher, 2, u64::MAX).expect("fill");
    assert!(cache.read_waiting("QmC0").is_ok());
    assert!(matches!(
        cache.read_waiting("QmMissing"),
        Err(StoreError::Cache(_))
    ));
}
