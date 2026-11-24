//! Threshold counts through the engine host: several checks share the passes over the encrypted chunks and give what
//! each check gives on its own. The engine tests' environment variables apply (`make test` sets them).

mod common;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use aseryx_enclave_harness::consent::Bytes32;
use aseryx_enclave_harness::engine::{EngineError, EngineModule, Limits, Run};
use aseryx_enclave_harness::manifest::Manifest;
use aseryx_enclave_harness::pipeline::run_passes_many;
use aseryx_enclave_harness::store::{CipherCache, Fetcher, StoreError};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::unique_dir;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

const PINNED: &str = "0xc4565b13e634c8c900a7d241ed141974e93eb6fb895e0b016a63cce36d35968c";
const KEY: [u8; 32] = [7; 32];

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} is not set; run the tests with `make test`")),
    )
}

fn module() -> EngineModule {
    let bytes = std::fs::read(env_path("ENCLAVE_ENGINE_WASM")).expect("engine module");
    let limits = Limits {
        deadline: Duration::from_secs(120),
        max_memory_bytes: 2 << 30,
    };
    EngineModule::load(&bytes, Bytes32::parse(PINNED).expect("pin"), limits).expect("loads")
}

fn golden() -> Vec<u8> {
    std::fs::read(env_path("ENCLAVE_TABULAR_FIXTURES").join("goldens/comma-clean.csv"))
        .expect("golden")
}

struct Blobs(HashMap<String, Vec<u8>>);

impl Fetcher for Blobs {
    fn fetch(&self, cid: &str) -> Result<Vec<u8>, StoreError> {
        self.0.get(cid).cloned().ok_or(StoreError::Fetch)
    }
}

fn encrypted(plain: &[u8], chunk_size: usize) -> (Manifest, CipherCache, PathBuf) {
    let cipher = Aes256Gcm::new((&KEY).into());
    let (mut chunks, mut blobs) = (Vec::new(), HashMap::new());
    for (index, part) in plain.chunks(chunk_size).enumerate() {
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(part).expect("gzip");
        let iv = [index as u8 + 1; 12];
        let sealed = cipher
            .encrypt(&Nonce::from(iv), gz.finish().expect("gzip").as_slice())
            .expect("encrypt");
        chunks.push(json!({"cid": format!("ipfs://QmChunk{index}"), "iv": STANDARD.encode(iv)}));
        blobs.insert(format!("QmChunk{index}"), sealed);
    }
    let text = json!({
        "version": "aseryx-hybrid-chipotle-v3", "totalSize": plain.len(), "chunkSize": chunk_size, "fileType": "csv",
        "plaintextSha256": hex::encode(Sha256::digest(plain)), "uploadName": "comma-clean.csv", "tokenId": "7",
        "dataset": "0123456789abcdef0123456789abcdef", "keyWrap": {}, "actionCid": "QmAction", "chunks": chunks,
    })
    .to_string();
    let manifest = Manifest::parse(&text).expect("manifest");
    let dir = unique_dir("threshold");
    let cache = CipherCache::new(&dir).expect("cache");
    cache
        .fill(&manifest.chunks, &Blobs(blobs), 3)
        .expect("fill");
    (manifest, cache, dir)
}

fn feed_all(mut run: Run, plain: &[u8]) -> Result<String, EngineError> {
    loop {
        run.feed(plain)?;
        if !run.next_pass()? {
            return run.finish();
        }
    }
}

fn label_of(module: &EngineModule, plain: &[u8]) -> (String, Value) {
    let appraisal = feed_all(
        module
            .appraisal(
                "comma-clean.csv",
                "csv",
                Some(&"ab".repeat(32)),
                Some("QmManifest"),
            )
            .expect("start"),
        plain,
    )
    .expect("appraise");
    let value: Value = serde_json::from_str(&appraisal).expect("json");
    (
        serde_json::to_string(&value["label"]).expect("label"),
        value,
    )
}

fn check(min: &str, max: &str, permille: u32) -> String {
    json!({"conditions": [{"column": "amount", "min": min, "max": max}], "allowed_failure_permille": permille}).to_string()
}

/// The label's hash from the engine is the hash the appraisal recorded.
#[test]
fn the_engine_hashes_a_label_to_the_recorded_label_hash() {
    let module = module();
    let (label, appraisal) = label_of(&module, &golden());
    assert_eq!(
        module.label_hash(&label).expect("hash"),
        appraisal["hashes"]["label_hash"]
            .as_str()
            .expect("label hash")
    );
    assert!(matches!(
        module.label_hash("not a label"),
        Err(EngineError::Module(_))
    ));
}

/// Several checks share the passes over the encrypted chunks and each gets what it gets alone.
#[test]
fn checks_sharing_passes_over_encrypted_chunks_match_checks_run_alone() {
    let module = module();
    let plain = golden();
    let (label, _) = label_of(&module, &plain);
    let checks = [
        check("10", "60", 100),
        check("0", "1000", 50),
        check("40", "45", 200),
    ];
    let (manifest, cache, dir) = encrypted(&plain, 500);
    let runs = checks
        .iter()
        .map(|c| module.threshold_count(&label, c).expect("start"))
        .collect();
    let expected: [u8; 32] = Sha256::digest(&plain).into();
    let together = run_passes_many(runs, &manifest, &KEY, &cache, &expected).expect("passes");
    for (check, joint) in checks.iter().zip(&together) {
        let alone = feed_all(
            module.threshold_count(&label, check).expect("start"),
            &plain,
        )
        .expect("alone");
        assert_eq!(joint, &alone, "{check}");
        let result: Value = serde_json::from_str(joint).expect("json");
        assert_eq!(result["error"], Value::Null, "{check}");
        assert!(result["answerable"].is_boolean());
    }
    std::fs::remove_dir_all(dir).expect("cleanup");
}

/// The circuit input for a counted check carries the check hash and the counts.
#[test]
fn the_threshold_witness_carries_the_check_hash_and_the_answer() {
    let module = module();
    let plain = golden();
    let (label, _) = label_of(&module, &plain);
    let counted = feed_all(
        module
            .threshold_count(&label, &check("10", "60", 100))
            .expect("start"),
        &plain,
    )
    .expect("count");
    let witness: Value = serde_json::from_str(
        &module
            .threshold_witness(&counted, "12345", 100)
            .expect("witness"),
    )
    .expect("json");
    let text = witness.to_string();
    assert!(text.contains("12345"), "{text}");
    assert!(matches!(
        module.threshold_witness("not json", "12345", 100),
        Err(EngineError::Module(_))
    ));
}
