//! The engine module runs under wasmtime and reproduces aseryx-engine's goldens.
//!
//! The tests read the module browsers run and the aseryx-engine fixtures from the paths in `ENCLAVE_ENGINE_WASM` and
//! `ENCLAVE_TABULAR_FIXTURES` (`make test` sets both) and fail when either is missing.

use aseryx_enclave_harness::consent::Bytes32;
use aseryx_enclave_harness::engine::{EngineError, EngineModule, Limits, Run};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

const PINNED: &str = "0x9bec14d49e3a56512cc0e54f7bd0d060841376ab94c301b7df7bfe3bba6a466d";
const RULES_HASH: &str =
    "196377069280065456317493222910811677995390882464815658788936813714641954860";

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} is not set; run the tests with `make test`")),
    )
}

fn limits() -> Limits {
    Limits {
        deadline: Duration::from_secs(120),
        max_memory_bytes: 2 << 30,
    }
}

fn wasm_bytes() -> Vec<u8> {
    std::fs::read(env_path("ENCLAVE_ENGINE_WASM")).expect("the engine module")
}

fn module() -> EngineModule {
    EngineModule::load(
        &wasm_bytes(),
        Bytes32::parse(PINNED).expect("pin"),
        limits(),
    )
    .expect("the pinned module loads")
}

fn run_over(mut run: Run, data: &[u8]) -> Result<String, EngineError> {
    loop {
        run.feed(data)?;
        if !run.next_pass()? {
            return run.finish();
        }
    }
}

fn fixtures() -> PathBuf {
    env_path("ENCLAVE_TABULAR_FIXTURES")
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).expect("JSON")
}

/// A module whose hash is not the pinned one is refused before it is compiled.
#[test]
fn a_module_with_another_hash_is_refused() {
    let mut bytes = wasm_bytes();
    bytes.push(0);
    match EngineModule::load(&bytes, Bytes32::parse(PINNED).expect("pin"), limits()) {
        Err(EngineError::NotPinned { found }) => assert_ne!(found.to_string(), PINNED),
        other => panic!("expected NotPinned, got {:?}", other.err()),
    }
}

/// A module that imports anything beyond the four wasm-bindgen functions is refused, so it cannot reach a clock, a
/// file or a network.
#[test]
fn a_module_that_imports_anything_else_is_refused() {
    let bytes = wat::parse_str(r#"(module (import "env" "now" (func)))"#).expect("wat");
    let pin = Bytes32(Sha256::digest(&bytes).into());
    assert!(
        matches!(EngineModule::load(&bytes, pin, limits()), Err(EngineError::Load(message)) if message.contains("unexpected import"))
    );
}

/// The module reports the version and frozen rules the plan pins.
#[test]
fn the_module_reports_the_pinned_rules() {
    let info = module().info().expect("info");
    assert_eq!(
        (
            info.version.as_str(),
            info.family.as_str(),
            info.model.as_str(),
            info.rules_version.as_str(),
            info.rules_hash.as_str()
        ),
        ("0.16.1", "tabular", "tabular_v12", "v12.0", RULES_HASH)
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

/// A run that outlives its deadline stops with a deadline error.
#[test]
fn a_run_past_its_deadline_is_stopped() {
    let slow = EngineModule::load(
        &wasm_bytes(),
        Bytes32::parse(PINNED).expect("pin"),
        Limits {
            deadline: Duration::from_millis(200),
            max_memory_bytes: 2 << 30,
        },
    )
    .expect("loads");
    let mut data = b"id,value,label\n".to_vec();
    (0..1_500_000)
        .for_each(|i| data.extend_from_slice(format!("{i},{},row{i}\n", i % 97).as_bytes()));
    let outcome = run_over(
        slow.appraisal("big.csv", "csv", None, None).expect("start"),
        &data,
    );
    assert!(matches!(outcome, Err(EngineError::Deadline)), "{outcome:?}");
}

/// A run that needs more memory than its limit allows stops with a memory error.
#[test]
fn a_run_over_its_memory_limit_is_stopped() {
    let tight = EngineModule::load(
        &wasm_bytes(),
        Bytes32::parse(PINNED).expect("pin"),
        Limits {
            deadline: Duration::from_secs(60),
            max_memory_bytes: 64 << 10,
        },
    )
    .expect("loads");
    let outcome = tight.appraisal("f.csv", "csv", None, None).map(|_| ());
    assert!(matches!(outcome, Err(EngineError::Memory)), "{outcome:?}");
}
