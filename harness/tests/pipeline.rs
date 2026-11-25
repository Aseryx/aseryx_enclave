//! A dataset read through encrypted chunks appraises exactly like the plaintext, and every way the chunks can be wrong is
//! caught. The engine tests' environment variables apply (`make test` sets them).

mod common;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use aseryx_enclave_harness::consent::Bytes32;
use aseryx_enclave_harness::engine::{EngineModule, Limits};
use aseryx_enclave_harness::error_code::ErrorCode;
use aseryx_enclave_harness::manifest::Manifest;
use aseryx_enclave_harness::pipeline::{PipelineError, run_passes};
use aseryx_enclave_harness::store::{CipherCache, Fetcher, StoreError};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::unique_dir;
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const LIMIT: u64 = u64::MAX;
const PINNED: &str = "0xc4565b13e634c8c900a7d241ed141974e93eb6fb895e0b016a63cce36d35968c";
const SALT: &str = "abababababababababababababababababababababababababababababababab";
const MANIFEST_ID: &str = "QmTestManifest";
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

fn temp_dir(name: &str) -> PathBuf {
    unique_dir(name)
}

/// Encrypts `plain` the way the web application does: chunks of `chunk_size`, gzip, AES-256-GCM with a fresh IV each.
/// Returns the manifest text and the ciphertext by content identifier.
fn encrypt(plain: &[u8], chunk_size: usize, key: &[u8; 32]) -> (String, HashMap<String, Vec<u8>>) {
    let cipher = Aes256Gcm::new(key.into());
    let mut chunks = Vec::new();
    let mut blobs = HashMap::new();
    for (index, part) in plain.chunks(chunk_size).enumerate() {
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(part).expect("gzip");
        let iv = [index as u8 + 1; 12];
        let sealed = cipher
            .encrypt(&Nonce::from(iv), gz.finish().expect("gzip").as_slice())
            .expect("encrypt");
        let cid = format!("QmChunk{index}");
        chunks.push(json!({"cid": format!("ipfs://{cid}"), "iv": STANDARD.encode(iv)}));
        blobs.insert(cid, sealed);
    }
    let manifest = json!({
        "version": "aseryx-hybrid-chipotle-v3", "totalSize": plain.len(), "chunkSize": chunk_size, "fileType": "csv",
        "plaintextSha256": hex::encode(Sha256::digest(plain)), "uploadName": "comma-clean.csv", "tokenId": "7",
        "dataset": "0123456789abcdef0123456789abcdef", "keyWrap": {"format": "aseryx-sealed-aes-key-v2"},
        "actionCid": "QmAction", "chunks": chunks,
    });
    (manifest.to_string(), blobs)
}

/// A fetcher over in-memory blobs that counts the fetches and fails for a missing one.
struct Blobs {
    blobs: HashMap<String, Vec<u8>>,
    fetches: AtomicUsize,
}

impl Blobs {
    fn new(blobs: HashMap<String, Vec<u8>>) -> Self {
        Self {
            blobs,
            fetches: AtomicUsize::new(0),
        }
    }
}

impl Fetcher for Blobs {
    fn fetch(&self, cid: &str, _: u64) -> Result<Vec<u8>, StoreError> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        self.blobs.get(cid).cloned().ok_or(StoreError::Fetch)
    }
}

fn start(module: &EngineModule, manifest: &Manifest) -> aseryx_enclave_harness::engine::Run {
    module
        .appraisal(
            &manifest.upload_name,
            &manifest.file_type,
            Some(SALT),
            Some(MANIFEST_ID),
        )
        .expect("start")
}

fn direct(module: &EngineModule, plain: &[u8]) -> String {
    let mut run = module
        .appraisal("comma-clean.csv", "csv", Some(SALT), Some(MANIFEST_ID))
        .expect("start");
    loop {
        run.feed(plain).expect("feed");
        if !run.next_pass().expect("pass") {
            return run.finish().expect("finish");
        }
    }
}

fn prepared(chunk_size: usize, key: &[u8; 32]) -> (Manifest, Blobs, CipherCache, PathBuf) {
    let (text, blobs) = encrypt(&golden(), chunk_size, key);
    let manifest = Manifest::parse(&text).expect("manifest");
    let dir = temp_dir("pipeline");
    let cache = CipherCache::new(&dir).expect("cache");
    let fetcher = Blobs::new(blobs);
    cache
        .fill(&manifest.chunks, &fetcher, 3, LIMIT)
        .expect("fill");
    (manifest, fetcher, cache, dir)
}

/// Reading the dataset through many small encrypted chunks gives the engine's output for the plaintext, byte for byte.
#[test]
fn encrypted_chunks_appraise_like_the_plaintext() {
    let module = module();
    let plain = golden();
    for chunk_size in [plain.len(), 4096, 1000, 77] {
        let (manifest, _, cache, dir) = prepared(chunk_size, &KEY);
        let expected: [u8; 32] = Sha256::digest(&plain).into();
        let output = run_passes(
            start(&module, &manifest),
            &manifest,
            &KEY,
            &cache,
            &expected,
        )
        .expect("passes");
        assert_eq!(output, direct(&module, &plain), "chunk size {chunk_size}");
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}

/// A registered hash that the plaintext does not have stops the run with the hash-mismatch code.
#[test]
fn a_plaintext_that_does_not_match_the_registered_hash_is_refused() {
    let module = module();
    let (manifest, _, cache, dir) = prepared(4096, &KEY);
    let error = run_passes(
        start(&module, &manifest),
        &manifest,
        &KEY,
        &cache,
        &[0x42; 32],
    )
    .expect_err("refused");
    assert!(matches!(error, PipelineError::HashMismatch));
    assert_eq!(error.code(), ErrorCode::HashMismatch);
    std::fs::remove_dir_all(dir).expect("cleanup");
}

/// A chunk that was altered, or the wrong key, fails authentication and reports a hash mismatch.
#[test]
fn an_altered_chunk_or_the_wrong_key_is_refused() {
    let module = module();
    let plain = golden();
    let expected: [u8; 32] = Sha256::digest(&plain).into();
    let (manifest, _, cache, dir) = prepared(4096, &KEY);
    let wrong_key = [8u8; 32];
    let error = run_passes(
        start(&module, &manifest),
        &manifest,
        &wrong_key,
        &cache,
        &expected,
    )
    .expect_err("wrong key");
    assert!(matches!(error, PipelineError::Chunk));
    assert_eq!(error.code(), ErrorCode::HashMismatch);
    let path = dir.join(&manifest.chunks[1].cid);
    let mut bytes = std::fs::read(&path).expect("chunk");
    bytes[5] ^= 1;
    std::fs::write(&path, bytes).expect("write");
    let error = run_passes(
        start(&module, &manifest),
        &manifest,
        &KEY,
        &cache,
        &expected,
    )
    .expect_err("altered");
    assert!(matches!(error, PipelineError::Chunk));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

/// A manifest whose size is not the plaintext's is refused, and a missing chunk is a fetch failure.
#[test]
fn a_wrong_size_or_a_missing_chunk_is_refused() {
    let module = module();
    let plain = golden();
    let expected: [u8; 32] = Sha256::digest(&plain).into();
    let (text, blobs) = encrypt(&plain, 4096, &KEY);
    let mut shorter: serde_json::Value = serde_json::from_str(&text).expect("json");
    shorter["totalSize"] = json!(plain.len() - 1);
    let manifest = Manifest::parse(&shorter.to_string()).expect("same chunk count");
    let dir = temp_dir("size");
    let cache = CipherCache::new(&dir).expect("cache");
    cache
        .fill(&manifest.chunks, &Blobs::new(blobs), 2, LIMIT)
        .expect("fill");
    let error = run_passes(
        start(&module, &manifest),
        &manifest,
        &KEY,
        &cache,
        &expected,
    )
    .expect_err("size");
    assert!(matches!(error, PipelineError::Size));
    std::fs::remove_file(dir.join(&manifest.chunks[2].cid)).expect("remove");
    let error = run_passes(
        start(&module, &manifest),
        &manifest,
        &KEY,
        &cache,
        &expected,
    )
    .expect_err("missing");
    assert_eq!(error.code(), ErrorCode::FetchFailed);
    std::fs::remove_dir_all(dir).expect("cleanup");
}

/// Each chunk is fetched once however many passes read it, a second fill fetches nothing, and a failing fetch stops
/// the fill with a fetch error.
#[test]
fn chunks_are_fetched_once_and_a_failed_fetch_stops_the_fill() {
    let (text, blobs) = encrypt(&golden(), 1000, &KEY);
    let manifest = Manifest::parse(&text).expect("manifest");
    let count = manifest.chunks.len();
    assert!(count > 3);
    let fetcher = Blobs::new(blobs);
    let dir = temp_dir("fetch");
    let cache = CipherCache::new(&dir).expect("cache");
    cache
        .fill(&manifest.chunks, &fetcher, 4, LIMIT)
        .expect("fill");
    assert_eq!(fetcher.fetches.load(Ordering::SeqCst), count);
    cache
        .fill(&manifest.chunks, &fetcher, 4, LIMIT)
        .expect("again");
    assert_eq!(fetcher.fetches.load(Ordering::SeqCst), count);
    let failing = Blobs::new(HashMap::new());
    let other = temp_dir("fail");
    let error = CipherCache::new(&other)
        .expect("cache")
        .fill(&manifest.chunks, &failing, 2, LIMIT)
        .expect_err("fails");
    assert!(matches!(error, StoreError::Fetch));
    assert!(
        failing.fetches.load(Ordering::SeqCst) < count,
        "the fill went on after a failure"
    );
    std::fs::remove_dir_all(dir).expect("cleanup");
    std::fs::remove_dir_all(other).expect("cleanup");
}

/// The cache holds ciphertext only: no file in it contains a line of the plaintext.
#[test]
fn the_cache_holds_only_ciphertext() {
    let (manifest, _, _, dir) = prepared(1000, &KEY);
    let plain = golden();
    let probe = &plain[plain.len() / 2..plain.len() / 2 + 24];
    for entry in std::fs::read_dir(&dir).expect("dir") {
        let bytes = std::fs::read(entry.expect("entry").path()).expect("file");
        assert!(
            !bytes.windows(probe.len()).any(|w| w == probe),
            "plaintext found in the cache"
        );
    }
    assert_eq!(
        std::fs::read_dir(&dir).expect("dir").count(),
        manifest.chunks.len()
    );
    std::fs::remove_dir_all(dir).expect("cleanup");
}

/// A chunk shorter than an AES-GCM tag is not ciphertext.
#[test]
fn a_chunk_shorter_than_a_tag_is_refused() {
    let (text, mut blobs) = encrypt(&golden(), 4096, &KEY);
    let manifest = Manifest::parse(&text).expect("manifest");
    blobs.insert(manifest.chunks[0].cid.clone(), vec![1, 2, 3]);
    let dir = temp_dir("short");
    let error = CipherCache::new(&dir)
        .expect("cache")
        .fill(&manifest.chunks, &Blobs::new(blobs), 2, LIMIT)
        .expect_err("short");
    assert!(matches!(error, StoreError::TooShort));
    std::fs::remove_dir_all(dir).expect("cleanup");
}

/// A fetcher that holds each chunk back for a while, so the passes start before the chunks have landed.
struct Late {
    inner: Blobs,
    delay: Duration,
}

impl Fetcher for Late {
    fn fetch(&self, cid: &str, max_bytes: u64) -> Result<Vec<u8>, StoreError> {
        std::thread::sleep(self.delay);
        self.inner.fetch(cid, max_bytes)
    }
}

/// Chunks that land while the passes run give the same output as chunks that were there before: the first pass waits for
/// each chunk in order, and the later passes find them all on disk.
#[test]
fn chunks_that_land_during_the_passes_give_the_same_output() {
    let module = module();
    let plain = golden();
    let expected: [u8; 32] = Sha256::digest(&plain).into();
    let (text, blobs) = encrypt(&plain, 1000, &KEY);
    let manifest = Manifest::parse(&text).expect("manifest");
    assert!(manifest.chunks.len() > 4, "the test needs several chunks");
    let dir = temp_dir("pipeline-late");
    let cache = CipherCache::new(&dir).expect("cache");
    let fetcher = Late {
        inner: Blobs::new(blobs),
        delay: Duration::from_millis(30),
    };
    let output = std::thread::scope(|scope| {
        cache.start_fetching(scope, &manifest.chunks, &fetcher, 2, LIMIT);
        let output = run_passes(
            start(&module, &manifest),
            &manifest,
            &KEY,
            &cache,
            &expected,
        );
        cache.cancel();
        output
    })
    .expect("passes");
    assert_eq!(output, direct(&module, &plain));
    let stats = cache.fetch_stats();
    assert_eq!(stats.chunks, manifest.chunks.len() as u64);
    assert_eq!(
        fetcher.inner.fetches.load(Ordering::SeqCst),
        manifest.chunks.len(),
        "every chunk is fetched once, however many passes read it"
    );
    std::fs::remove_dir_all(dir).expect("cleanup");
}

/// A chunk that never arrives ends the passes with the fetch code instead of hanging them.
#[test]
fn a_chunk_that_never_arrives_ends_the_passes_with_a_fetch_failure() {
    let module = module();
    let plain = golden();
    let expected: [u8; 32] = Sha256::digest(&plain).into();
    let (text, mut blobs) = encrypt(&plain, 1000, &KEY);
    let manifest = Manifest::parse(&text).expect("manifest");
    blobs.remove("QmChunk3");
    let dir = temp_dir("pipeline-missing");
    let cache = CipherCache::new(&dir).expect("cache");
    let fetcher = Late {
        inner: Blobs::new(blobs),
        delay: Duration::from_millis(10),
    };
    let error = std::thread::scope(|scope| {
        cache.start_fetching(scope, &manifest.chunks, &fetcher, 2, LIMIT);
        let output = run_passes(
            start(&module, &manifest),
            &manifest,
            &KEY,
            &cache,
            &expected,
        );
        cache.cancel();
        output
    })
    .expect_err("a chunk is missing");
    assert_eq!(error.code(), ErrorCode::FetchFailed);
    std::fs::remove_dir_all(dir).expect("cleanup");
}
