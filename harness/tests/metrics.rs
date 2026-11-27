//! The metrics object: its exact shape, the cap on passes, the peak memory read from `/proc`, and values that stay within
//! what the API accepts.

mod common;

use aseryx_enclave_harness::metrics::{MAX_PASSES, Recorder, Stage, rss_peak_from};
use aseryx_enclave_harness::pipeline::PassTiming;
use aseryx_enclave_harness::store::CipherCache;
use common::unique_dir;
use std::time::Duration;

fn pass(chunks: u64) -> PassTiming {
    PassTiming {
        wait: Duration::from_millis(5),
        decrypt: Duration::from_millis(10),
        decompress: Duration::from_millis(20),
        parse: Duration::from_millis(40),
        chunks,
    }
}

/// `VmHWM` is the peak resident memory in kilobytes; anything else is nothing.
#[test]
fn the_peak_resident_memory_is_read_from_the_status_text() {
    let status = "Name:\taseryx\nVmPeak:\t  900000 kB\nVmHWM:\t  123456 kB\nVmRSS:\t  100000 kB\n";
    assert_eq!(rss_peak_from(status), Some(123_456 * 1024));
    for bad in [
        "",
        "VmRSS: 5 kB\n",
        "VmHWM: x kB\n",
        "VmHWM: 5\n",
        "VmHWM: 18446744073709551615 kB\n",
    ] {
        assert_eq!(rss_peak_from(bad), None, "{bad:?}");
    }
}

/// Stage times add up, the wait is the passes' wait, and a stage that never ran is 0.
#[test]
fn stages_and_waits_are_added_up() {
    let recorder = Recorder::new();
    let cache = CipherCache::new(&unique_dir("metrics-stages")).expect("cache");
    recorder.time(Stage::Checks, || {
        std::thread::sleep(Duration::from_millis(15))
    });
    recorder.time(Stage::Checks, || {
        std::thread::sleep(Duration::from_millis(15))
    });
    recorder.record_pass(pass(3));
    recorder.record_pass(pass(3));
    recorder.proof_made();
    recorder.token_refreshed();
    recorder.token_refreshed();
    let m = recorder.snapshot_with(&cache, 777);
    assert!(m["stageMs"]["checks"].as_u64().expect("checks") >= 30);
    assert_eq!(m["stageMs"]["claim"], 0);
    assert_eq!(m["stageMs"]["wait"], 10);
    assert_eq!(m["proofs"], 1);
    assert_eq!(m["tokenRefreshes"], 2);
    assert_eq!(m["rssPeakBytes"], 777);
    assert_eq!(m["passes"].as_array().expect("passes").len(), 2);
    assert_eq!(m["passes"][0]["parseMs"], 40);
}

/// More passes than the object may list are added into the last one listed, so nothing is dropped and the object stays within
/// what the API accepts.
#[test]
fn passes_beyond_the_cap_are_added_into_the_last_listed() {
    let recorder = Recorder::new();
    let cache = CipherCache::new(&unique_dir("metrics-cap")).expect("cache");
    for _ in 0..MAX_PASSES + 4 {
        recorder.record_pass(pass(2));
    }
    let m = recorder.snapshot_with(&cache, 0);
    let passes = m["passes"].as_array().expect("passes");
    assert_eq!(passes.len(), MAX_PASSES);
    assert_eq!(passes[0]["chunks"], 2);
    assert_eq!(passes[MAX_PASSES - 1]["chunks"], 2 * 5);
    assert_eq!(passes[MAX_PASSES - 1]["parseMs"], 40 * 5);
    assert_eq!(
        m["stageMs"]["wait"],
        5 * (MAX_PASSES as u64 + 4),
        "the wait counts every pass"
    );
}

/// Values past what the canonical JSON can carry are held at 2^53 - 1, so the object still signs.
#[test]
fn a_value_past_the_signable_limit_is_held_at_the_limit() {
    let recorder = Recorder::new();
    let cache = CipherCache::new(&unique_dir("metrics-limit")).expect("cache");
    let m = recorder.snapshot_with(&cache, u64::MAX);
    let limit = (1u64 << 53) - 1;
    assert_eq!(m["rssPeakBytes"], limit);
    assert!(aseryx_enclave_harness::consent::canonical_json(&m).is_ok());
}
