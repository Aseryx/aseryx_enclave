//! The engine linked into the workload reproduces aseryx-engine's goldens, obeys its limits and is pinned by its hash.
//!
//! The tests read the aseryx-engine fixtures from the path in `ENCLAVE_TABULAR_FIXTURES` (`make test` sets it) and fail
//! when it is missing.

mod common;

use aseryx_enclave_harness::consent::Bytes32;
use aseryx_enclave_harness::engine::{EngineError, Limits, NativeEngine, Run};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

const RULES_HASH: &str =
    "196377069280065456317493222910811677995390882464815658788936813714641954860";
const WATCHDOG_CHILD: &str = "ENCLAVE_TEST_WATCHDOG_CHILD";

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} is not set; run the tests with `make test`")),
    )
}

fn module() -> NativeEngine {
    common::native_engine()
}

/// Runs a whole file through a run and returns the number of readings with the result.
fn read_over(mut run: Run, data: &[u8]) -> Result<(u32, String), EngineError> {
    let mut readings = 0;
    loop {
        run.feed(data)?;
        readings += 1;
        if !run.next_pass()? {
            return Ok((readings, run.finish()?));
        }
    }
}

fn run_over(run: Run, data: &[u8]) -> Result<String, EngineError> {
    read_over(run, data).map(|(_, result)| result)
}

fn fixtures() -> PathBuf {
    env_path("ENCLAVE_TABULAR_FIXTURES")
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).expect("JSON")
}

/// An engine is started only with the hash of the library this build is linked with.
#[test]
fn a_pin_that_is_not_the_linked_librarys_hash_is_refused() {
    let linked = NativeEngine::library_sha256();
    let mut other = linked;
    other.0[0] ^= 1;
    match NativeEngine::new(other, common::engine_limits()) {
        Err(EngineError::NotPinned { found }) => assert_eq!(found, linked),
        other => panic!("expected NotPinned, got {:?}", other.err()),
    }
    assert!(NativeEngine::new(linked, common::engine_limits()).is_ok());
}

/// The library this build is linked with is the vendored release, by its recorded hash.
#[test]
fn the_linked_library_is_the_vendored_one() {
    let recorded = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../engine/libaseryx_engine_ffi.a.sha256"),
    )
    .expect("the library's .sha256");
    let hash = recorded.split_whitespace().next().expect("hash");
    assert_eq!(
        NativeEngine::library_sha256(),
        Bytes32::parse(&format!("0x{hash}")).expect("hex")
    );
}

/// The engine reports the version and frozen rules the plan pins.
#[test]
fn the_engine_reports_the_pinned_rules() {
    let info = module().info().expect("info");
    assert_eq!(
        (
            info.version.as_str(),
            info.family.as_str(),
            info.model.as_str(),
            info.rules_version.as_str(),
            info.rules_hash.as_str()
        ),
        ("0.17.0", "tabular", "tabular_v12", "v12.0", RULES_HASH)
    );
}

/// Every golden appraises to its witness and to the score, band, factors and hashes the fixtures record.
#[test]
fn every_golden_appraises_to_its_witness_and_recorded_values() {
    let module = module();
    let expected = json(
        &std::fs::read_to_string(fixtures().join("goldens/expected.json")).expect("expected.json"),
    );
    let files = expected["files"].as_object().expect("files");
    assert_eq!(files.len(), 16);
    for (name, want) in files {
        let data = std::fs::read(fixtures().join("goldens").join(name)).expect("golden");
        let format = name.rsplit('.').next().expect("extension");
        let result = json(
            &run_over(
                module.appraisal(name, format, None, None).expect("start"),
                &data,
            )
            .expect(name),
        );
        let witness = json(
            &std::fs::read_to_string(fixtures().join(format!("{name}.witness.json")))
                .expect("witness"),
        );
        let mut got = result["witness"].clone();
        got.as_object_mut().expect("witness").remove("rules_hash");
        let mut recorded = witness;
        recorded
            .as_object_mut()
            .expect("witness")
            .remove("rules_hash");
        assert_eq!(got, recorded, "{name} witness");
        assert_eq!(result["quality"]["score"], want["score"], "{name} score");
        assert_eq!(result["quality"]["band"], want["band"], "{name} band");
        assert_eq!(
            result["quality"]["factors"], want["factors"],
            "{name} factors"
        );
        for hash in ["plaintext_hash", "label_hash", "schema_hash"] {
            assert_eq!(result["hashes"][hash], want[hash], "{name} {hash}");
        }
    }
}

/// A label check of a golden reruns its label and reproduces the same hashes.
#[test]
fn a_label_check_reproduces_the_label_of_a_golden() {
    let module = module();
    let data = std::fs::read(fixtures().join("goldens/comma-clean.csv")).expect("golden");
    let appraised = json(
        &run_over(
            module
                .appraisal("comma-clean.csv", "csv", None, None)
                .expect("start"),
            &data,
        )
        .expect("appraise"),
    );
    let label = serde_json::to_string(&appraised["label"]).expect("label");
    let checked =
        json(&run_over(module.label_check(&label).expect("start"), &data).expect("check"));
    assert_eq!(checked["error"], Value::Null);
    assert_eq!(
        checked["plaintext_hash"],
        appraised["hashes"]["plaintext_hash"]
    );
    assert_eq!(checked["label_hash"], appraised["hashes"]["label_hash"]);
    assert_eq!(checked["inputs_commitment"], appraised["inputsCommitment"]);
}

/// An argument the engine refuses comes back as the engine's own error.
#[test]
fn an_argument_the_engine_refuses_is_reported_as_its_error() {
    let module = module();
    assert!(matches!(
        module.appraisal("f.csv", "csv", Some("not hex"), None),
        Err(EngineError::Module(_))
    ));
    assert!(matches!(
        module.appraisal("f.csv", "csv", None, Some("bad id!")),
        Err(EngineError::Module(_))
    ));
}

/// A run that outlives its deadline stops with a deadline error at its next call.
#[test]
fn a_run_past_its_deadline_is_stopped() {
    let slow = NativeEngine::new(
        NativeEngine::library_sha256(),
        Limits {
            deadline: Duration::from_millis(50),
            ..common::engine_limits()
        },
    )
    .expect("starts");
    let mut run = slow.appraisal("big.csv", "csv", None, None).expect("start");
    std::thread::sleep(Duration::from_millis(120));
    let outcome = run.feed(b"id,value\n1,2\n");
    assert!(matches!(outcome, Err(EngineError::Deadline)), "{outcome:?}");
    assert!(matches!(run.next_pass(), Err(EngineError::Deadline)));
}

/// A smaller pass 2 budget reads a large file more times and changes no result.
#[test]
fn a_smaller_pass_two_budget_adds_readings_and_changes_no_result() {
    let mut data = b"id,region,amount\n".to_vec();
    (0..120_000).for_each(|i| {
        data.extend_from_slice(format!("{i},r{},{}\n", i % 5, (i * 7919) % 1000).as_bytes());
    });
    let with = |budget: u64| {
        let engine = NativeEngine::new(
            NativeEngine::library_sha256(),
            Limits {
                pass_two_budget_bytes: budget,
                ..common::engine_limits()
            },
        )
        .expect("starts");
        read_over(
            engine.appraisal("a.csv", "csv", None, None).expect("start"),
            &data,
        )
        .expect("appraises")
    };
    let (large_readings, large) = with(1 << 30);
    let (small_readings, small) = with(1 << 20);
    assert_eq!(large_readings, 3);
    assert!(
        small_readings > large_readings,
        "{small_readings} readings at 1 MiB"
    );
    assert_eq!(large, small);
}

/// A budget outside the engine's range is refused when the appraisal starts.
#[test]
fn a_pass_two_budget_out_of_range_is_refused_at_the_start() {
    let engine = NativeEngine::new(
        NativeEngine::library_sha256(),
        Limits {
            pass_two_budget_bytes: 1,
            ..common::engine_limits()
        },
    )
    .expect("starts");
    assert!(matches!(
        engine.appraisal("a.csv", "csv", None, None),
        Err(EngineError::Module(_))
    ));
}

/// A run that stays open past its deadline and the grace period ends the process: a call into the engine cannot be
/// interrupted, so the watchdog does. The test runs this binary again as the child that opens such a run.
#[test]
fn a_run_left_open_past_its_grace_period_ends_the_process() {
    if std::env::var_os(WATCHDOG_CHILD).is_some() {
        let engine = NativeEngine::new(
            NativeEngine::library_sha256(),
            Limits {
                deadline: Duration::from_millis(200),
                hard_grace: Duration::from_millis(500),
                pass_two_budget_bytes: 256 << 20,
            },
        )
        .expect("starts");
        let _open = engine.appraisal("a.csv", "csv", None, None).expect("start");
        std::thread::sleep(Duration::from_secs(30));
        std::process::exit(0);
    }
    let began = Instant::now();
    let status = Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            "a_run_left_open_past_its_grace_period_ends_the_process",
            "--nocapture",
        ])
        .env(WATCHDOG_CHILD, "1")
        .status()
        .expect("runs");
    assert_eq!(status.code(), Some(1), "the watchdog's exit status");
    assert!(
        began.elapsed() < Duration::from_secs(20),
        "{:?}",
        began.elapsed()
    );
}
