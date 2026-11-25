//! A job from claim to signed result against stubs of everything outside the workload: the attestation sidecar, the
//! API, Lit, the chain, IPFS and the prover. The engine and the pipeline are real. The engine tests' environment
//! variables apply (`make test` sets them).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
mod common;

use aseryx_enclave_harness::attest::{AttestError, Attestor};
use aseryx_enclave_harness::chain::{ChainError, ChainReader, DatasetRecord};
use aseryx_enclave_harness::check::parse_check;
use aseryx_enclave_harness::claim::{ClaimError, JobSource};
use aseryx_enclave_harness::consent::{
    Address, AppraisalJob, Bytes32, Domain, ThresholdJob, Uint256, result_digest,
};
use aseryx_enclave_harness::engine::{EngineModule, Limits};
use aseryx_enclave_harness::error_code::ErrorCode;
use aseryx_enclave_harness::job::{
    ApiError, CheckSpec, Job, JobApi, JobInputs, JobKind, ProveError, Prover, Services, run_job,
};
use aseryx_enclave_harness::keys::verify_result_signature;
use aseryx_enclave_harness::label::{open_label, seal_label};
use aseryx_enclave_harness::lit::{KeyReleaser, LitError, SealedResponse};
use aseryx_enclave_harness::manifest::Manifest;
use aseryx_enclave_harness::metrics::Recorder;
use aseryx_enclave_harness::result::Proof;
use aseryx_enclave_harness::runtime_data::RuntimeData;
use aseryx_enclave_harness::store::{
    CipherCache, DISK_RESERVE_BYTES, Fetcher, MAX_MANIFEST_BYTES, StoreError, UrlFetcher,
    chunk_limit,
};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::unique_dir;
use flate2::Compression;
use flate2::write::GzEncoder;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeS, Serializable};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const PINNED: &str = "0xc4565b13e634c8c900a7d241ed141974e93eb6fb895e0b016a63cce36d35968c";
const KEY: [u8; 32] = [7; 32];
const JOB: &str = "0xd828621b01841c9a5630937da5ffb06cf43417178bee1149d90b84ca148408fa";
const WORKLOAD: &str = "0xf6a7a4f67b3edf6d9d7c7098f9b514f53f263be0a4e32fbac2ee585d6972f20f";
const DATASET: &str = "0123456789abcdef0123456789abcdef";
const MANIFEST_CID: &str = "QmManifest";
const CONTRACT: &str = "0x5Db410D07931Efc7CF1d01545e773992Ab1988b2";

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} is not set; run the tests with `make test`")),
    )
}

fn wasm() -> Vec<u8> {
    std::fs::read(env_path("ENCLAVE_ENGINE_WASM")).expect("engine module")
}

fn engine() -> EngineModule {
    let limits = Limits {
        deadline: Duration::from_secs(120),
        max_memory_bytes: 2 << 30,
    };
    EngineModule::load(&wasm(), Bytes32::parse(PINNED).expect("pin"), limits).expect("loads")
}

fn golden() -> Vec<u8> {
    std::fs::read(env_path("ENCLAVE_TABULAR_FIXTURES").join("goldens/comma-clean.csv"))
        .expect("golden")
}

fn domain() -> Domain {
    Domain::new(43113, Address::parse(CONTRACT).expect("address")).expect("domain")
}

/// The world outside the workload, as the stubs share it.
struct World {
    plain: Vec<u8>,
    manifest_text: String,
    blobs: HashMap<String, Vec<u8>>,
    record: DatasetRecord,
    posted: Mutex<Vec<Value>>,
    released: Mutex<Vec<Value>>,
    proved: Mutex<Vec<String>>,
    /// Each fetch from the gateway and the most it was allowed to return.
    fetches: Mutex<Vec<(String, u64)>>,
}

fn world() -> World {
    let plain = golden();
    let cipher = Aes256Gcm::new((&KEY).into());
    let (mut chunks, mut blobs) = (Vec::new(), HashMap::new());
    for (index, part) in plain.chunks(4096).enumerate() {
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(part).expect("gzip");
        let iv = [index as u8 + 1; 12];
        let sealed = cipher
            .encrypt(&Nonce::from(iv), gz.finish().expect("gzip").as_slice())
            .expect("encrypt");
        chunks.push(json!({"cid": format!("ipfs://QmChunk{index}"), "iv": STANDARD.encode(iv)}));
        blobs.insert(format!("QmChunk{index}"), sealed);
    }
    let hash: [u8; 32] = Sha256::digest(&plain).into();
    let manifest_text = json!({
        "version": "aseryx-hybrid-chipotle-v3", "totalSize": plain.len(), "chunkSize": 4096, "fileType": "csv",
        "plaintextSha256": hex::encode(hash), "uploadName": "comma-clean.csv", "tokenId": "7", "dataset": DATASET,
        "keyWrap": {"format": "aseryx-sealed-aes-key-v2"}, "actionCid": "QmAction", "chunks": chunks,
    })
    .to_string();
    blobs.insert(MANIFEST_CID.to_owned(), manifest_text.clone().into_bytes());
    World {
        plain,
        manifest_text,
        blobs,
        record: DatasetRecord {
            plaintext_hash: Bytes32(hash),
            manifest_cid: MANIFEST_CID.to_owned(),
            latest_expiry: 0,
        },
        posted: Mutex::new(Vec::new()),
        released: Mutex::new(Vec::new()),
        proved: Mutex::new(Vec::new()),
        fetches: Mutex::new(Vec::new()),
    }
}

struct Fixed(DatasetRecord);
impl ChainReader for Fixed {
    fn get_dataset(&self, _: &Uint256, _: &str) -> Result<DatasetRecord, ChainError> {
        Ok(self.0.clone())
    }
}

struct Blobs<'a>(&'a World);
impl Fetcher for Blobs<'_> {
    fn fetch(&self, cid: &str, max_bytes: u64) -> Result<Vec<u8>, StoreError> {
        self.0
            .fetches
            .lock()
            .expect("lock")
            .push((cid.to_owned(), max_bytes));
        self.0.blobs.get(cid).cloned().ok_or(StoreError::Fetch)
    }
}

struct Token;
impl Attestor for Token {
    fn attest(&self, _: &RuntimeData) -> Result<String, AttestError> {
        Ok("aaa.bbb.ccc".to_owned())
    }
}

/// Mints a token that records the logical time it was minted at.
struct Minting<'a>(&'a AtomicU64);
impl Attestor for Minting<'_> {
    fn attest(&self, _: &RuntimeData) -> Result<String, AttestError> {
        Ok(format!("{}.x.y", self.0.load(Ordering::SeqCst)))
    }
}

fn token_is_fresh(token: &str, clock: &AtomicU64, max_age: u64) -> bool {
    let minted: u64 = token
        .split('.')
        .next()
        .and_then(|t| t.parse().ok())
        .unwrap_or(0);
    clock.load(Ordering::SeqCst).saturating_sub(minted) <= max_age
}

/// The API, refusing a token older than `max_age`; fetching a job takes 700 seconds.
struct Expiring<'a> {
    inner: &'a dyn JobApi,
    clock: &'a AtomicU64,
    max_age: u64,
}
impl JobApi for Expiring<'_> {
    fn job(&self, token: &str, runtime_data: &str) -> Result<Job, ApiError> {
        if !token_is_fresh(token, self.clock, self.max_age) {
            return Err(ApiError);
        }
        let inputs = self.inner.job(token, runtime_data);
        self.clock.fetch_add(700, Ordering::SeqCst);
        inputs
    }
    fn post_result(&self, body: &Value) -> Result<(), ApiError> {
        if token_is_fresh(
            body["token"].as_str().unwrap_or(""),
            self.clock,
            self.max_age,
        ) {
            self.inner.post_result(body)
        } else {
            Err(ApiError)
        }
    }
}

/// The relay, refusing a token older than `max_age`.
struct ExpiringRelay<'a> {
    inner: &'a dyn KeyReleaser,
    clock: &'a AtomicU64,
    max_age: u64,
}
impl KeyReleaser for ExpiringRelay<'_> {
    fn release(&self, request: &Value) -> Result<SealedResponse, LitError> {
        if token_is_fresh(
            request["token"].as_str().unwrap_or(""),
            self.clock,
            self.max_age,
        ) {
            self.inner.release(request)
        } else {
            Err(LitError::Denied)
        }
    }
}

/// A prover that makes the logical clock run on.
struct Slow<'a> {
    inner: &'a dyn Prover,
    clock: &'a AtomicU64,
    seconds: u64,
}
impl Prover for Slow<'_> {
    fn prove(&self, circuit: &str, witness: &str) -> Result<Proof, ProveError> {
        self.clock.fetch_add(self.seconds, Ordering::SeqCst);
        self.inner.prove(circuit, witness)
    }
}

/// A dataset job fetches no evidence.
struct NoEvidence;
impl UrlFetcher for NoEvidence {
    fn get(&self, _: &str, _: u64) -> Result<Vec<u8>, StoreError> {
        panic!("a dataset job fetched evidence")
    }
}

struct Assigns(Result<Bytes32, ClaimError>);
impl JobSource for Assigns {
    fn claim(&self, _: &str, _: &RuntimeData, _: u32) -> Result<Bytes32, ClaimError> {
        self.0
    }
}

struct Api<'a> {
    world: &'a World,
    inputs: Result<JobInputs, ApiError>,
    post_fails: bool,
}
impl JobApi for Api<'_> {
    fn job(&self, _: &str, _: &str) -> Result<Job, ApiError> {
        self.inputs
            .clone()
            .map(|inputs| Job::Data(Box::new(inputs)))
            .map_err(|_| ApiError)
    }
    fn post_result(&self, body: &Value) -> Result<(), ApiError> {
        self.world.posted.lock().expect("lock").push(body.clone());
        if self.post_fails {
            Err(ApiError)
        } else {
            Ok(())
        }
    }
}

/// A relay stub that seals the dataset key, as the action does, to the response key named in the runtime data it is
/// given. It knows the job's consent as the API does, and refuses a request that carries anything but the three fields.
struct Lit<'a> {
    world: &'a World,
    outcome: Result<(), LitError>,
    consent: Option<(Value, &'static str)>,
}
impl KeyReleaser for Lit<'_> {
    fn release(&self, request: &Value) -> Result<SealedResponse, LitError> {
        let mut names: Vec<&str> = request
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["action", "runtimeData", "sealed", "token"],
            "the workload sends the sealed key and the proof, nothing else"
        );
        assert_eq!(request["action"], "decrypt");
        self.world
            .released
            .lock()
            .expect("lock")
            .push(request.clone());
        self.outcome?;
        let runtime: Value = serde_json::from_slice(
            &STANDARD
                .decode(request["runtimeData"].as_str().expect("runtime"))
                .expect("b64"),
        )
        .expect("json");
        let public = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(
            &hex::decode(runtime["responsePublicKey"].as_str().expect("key")).expect("hex"),
        )
        .expect("key");
        let (consent, kind) = self.consent.as_ref().expect("a job with a consent");
        let digest = digest_of(consent, kind);
        let info =
            format!(r#"{{"consent":"{digest}","domain":"aseryx/attested-key-response/v1"}}"#);
        let (encapped, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &public,
            info.as_bytes(),
            &KEY,
            &[],
        )
        .expect("seal");
        Ok(SealedResponse {
            enc: URL_SAFE_NO_PAD.encode(encapped.to_bytes()),
            ciphertext: URL_SAFE_NO_PAD.encode(ct),
        })
    }
}

fn digest_of(consent: &Value, kind: &str) -> Bytes32 {
    match kind {
        "appraisal" => serde_json::from_value::<AppraisalJob>(consent.clone())
            .expect("consent")
            .digest(domain()),
        _ => serde_json::from_value::<ThresholdJob>(consent.clone())
            .expect("consent")
            .digest(domain()),
    }
}

struct Proves<'a> {
    world: &'a World,
    fails: bool,
}
impl Prover for Proves<'_> {
    fn prove(&self, circuit: &str, _: &str) -> Result<Proof, ProveError> {
        self.world
            .proved
            .lock()
            .expect("lock")
            .push(circuit.to_owned());
        if self.fails {
            return Err(ProveError);
        }
        let count = if circuit.starts_with("threshold") {
            7
        } else {
            12
        };
        Ok(Proof {
            text: r#"{"protocol":"groth16"}"#.to_owned(),
            public_signals: (0..count).map(|n| n.to_string()).collect(),
        })
    }
}

fn appraisal_consent(world: &World) -> Value {
    json!({
        "tokenId": "7", "dataset": DATASET, "manifestCid": MANIFEST_CID, "plaintextHash": world.record.plaintext_hash.to_string(),
        "family": "tabular", "rulesVersion": "v12.0", "workloadIdentity": WORKLOAD, "jobId": JOB,
        "minBootloaderSvn": 10, "minTeeSvn": 0, "minSnpSvn": 23, "minMicrocodeSvn": 84, "expiresAt": "1795556000",
    })
}

fn appraisal_inputs(world: &World) -> JobInputs {
    JobInputs {
        kind: JobKind::Appraisal,
        consent: appraisal_consent(world),
        consent_signature: "0x00".to_owned(),
        token_id: "7".to_owned(),
        dataset: DATASET.to_owned(),
        manifest_cid: MANIFEST_CID.to_owned(),
        family: "tabular".to_owned(),
        checks: Vec::new(),
        encrypted_label: None,
    }
}

fn run(
    world: &World,
    inputs: Result<JobInputs, ApiError>,
    tweak: impl FnOnce(&mut Tweaks),
) -> Result<(), ErrorCode> {
    let mut t = Tweaks {
        claim: Ok(Bytes32::parse(JOB).expect("job")),
        lit: Ok(()),
        prove_fails: false,
        post_fails: false,
        record: world.record.clone(),
        token_max_age: None,
        disk_free: None,
    };
    tweak(&mut t);
    let dir = unique_dir("job");
    let cache = match t.disk_free {
        Some(free) => CipherCache::with_free_space(&dir, move |_| Ok(free)),
        None => CipherCache::new(&dir),
    }
    .expect("cache");
    let engine = engine();
    let chain = Fixed(t.record);
    let fetcher = Blobs(world);
    let relay_consent = inputs.as_ref().ok().map(|i| {
        let kind = match i.kind {
            JobKind::Appraisal => "appraisal",
            JobKind::Threshold => "threshold",
        };
        (i.consent.clone(), kind)
    });
    let clock = AtomicU64::new(0);
    let (source, api, lit, prover) = (
        Assigns(t.claim),
        Api {
            world,
            inputs,
            post_fails: t.post_fails,
        },
        Lit {
            world,
            outcome: t.lit,
            consent: relay_consent,
        },
        Proves {
            world,
            fails: t.prove_fails,
        },
    );
    let (timed_attestor, timed_api, timed_lit, slow_prover) = (
        Minting(&clock),
        Expiring {
            inner: &api,
            clock: &clock,
            max_age: t.token_max_age.unwrap_or(0),
        },
        ExpiringRelay {
            inner: &lit,
            clock: &clock,
            max_age: t.token_max_age.unwrap_or(0),
        },
        Slow {
            inner: &prover,
            clock: &clock,
            seconds: 700,
        },
    );
    let (attestor, job_api, releaser, prover): (
        &dyn Attestor,
        &dyn JobApi,
        &dyn KeyReleaser,
        &dyn Prover,
    ) = if t.token_max_age.is_some() {
        (&timed_attestor, &timed_api, &timed_lit, &slow_prover)
    } else {
        (&Token, &api, &lit, &prover)
    };
    let metrics = Recorder::new();
    let services = Services {
        attestor,
        source: &source,
        api: job_api,
        releaser,
        chain: &chain,
        fetcher: &fetcher,
        evidence: &NoEvidence,
        cache: &cache,
        engine: &engine,
        prover,
        engine_module_sha256: Bytes32::parse(PINNED).expect("pin"),
        domain: domain(),
        memory_gb: 4,
        parallel_fetches: 3,
        appraisal_circuit: "tabular_appraisal_r7",
        metrics: &metrics,
    };
    let outcome = run_job(&services);
    std::fs::remove_dir_all(dir).expect("cleanup");
    outcome
}

struct Tweaks {
    claim: Result<Bytes32, ClaimError>,
    lit: Result<(), LitError>,
    prove_fails: bool,
    post_fails: bool,
    record: DatasetRecord,
    /// When set, tokens carry the time they were minted and the API and relay refuse one older than this many seconds,
    /// fetching the job and proving take 700 seconds each.
    token_max_age: Option<u64>,
    /// When set, the disk holding the chunk cache has this many free bytes.
    disk_free: Option<u64>,
}

fn posted_signature_verifies(body: &Value, result: &Value) -> bool {
    let runtime: Value = serde_json::from_slice(
        &STANDARD
            .decode(body["runtimeData"].as_str().expect("runtime"))
            .expect("b64"),
    )
    .expect("json");
    let signature: [u8; 65] = hex::decode(body_signature(body, result).trim_start_matches("0x"))
        .expect("hex")
        .try_into()
        .expect("65 bytes");
    verify_result_signature(
        runtime["resultPublicKey"].as_str().expect("key"),
        &result_digest(result).expect("digest"),
        &signature,
    ) == Ok(true)
}

fn body_signature(body: &Value, result: &Value) -> String {
    if let Some(list) = body["results"].as_array() {
        return list.iter().find(|e| e["result"] == *result).expect("entry")["signature"]
            .as_str()
            .expect("signature")
            .to_owned();
    }
    body["signature"].as_str().expect("signature").to_owned()
}

/// An appraisal job runs from claim to a signed result whose label opens under the dataset key.
#[test]
fn an_appraisal_job_posts_a_signed_result() {
    let w = world();
    assert_eq!(run(&w, Ok(appraisal_inputs(&w)), |_| {}), Ok(()));
    let posted = w.posted.lock().expect("lock").clone();
    assert_eq!(posted.len(), 1);
    let body = &posted[0];
    assert_eq!(
        (
            body["action"].as_str(),
            body["kind"].as_str(),
            body["token"].as_str()
        ),
        (Some("result"), Some("appraisal"), Some("aaa.bbb.ccc"))
    );
    let result = &body["result"];
    assert_eq!(
        (
            result["jobId"].as_str(),
            result["kind"].as_str(),
            result["circuitName"].as_str()
        ),
        (Some(JOB), Some("appraisal"), Some("tabular_appraisal_r7"))
    );
    assert_eq!(result["plaintextHash"], w.record.plaintext_hash.to_string());
    assert_eq!(
        result["rulesHash"],
        "196377069280065456317493222910811677995390882464815658788936813714641954860"
    );
    assert!(posted_signature_verifies(body, result));
    let label = open_label(result["encryptedLabel"].as_str().expect("envelope"), &KEY)
        .expect("label opens under the dataset key");
    assert_eq!(
        engine().label_hash(&label).expect("hash"),
        result["labelHash"].as_str().expect("label hash")
    );
    assert_eq!(*w.proved.lock().expect("lock"), ["tabular_appraisal_r7"]);
    let released = w.released.lock().expect("lock").clone();
    assert_eq!(released.len(), 1);
    assert_eq!(
        (
            released[0]["action"].as_str(),
            released[0]["token"].as_str()
        ),
        (Some("decrypt"), Some("aaa.bbb.ccc"))
    );
    assert_eq!(
        released[0]["sealed"],
        json!({"format": "aseryx-sealed-aes-key-v2"})
    );
    assert!(
        !posted[0].to_string().contains("comma-clean"),
        "a file name reached the API"
    );
}

fn threshold_inputs(w: &World, label_hash: &str, envelope: &str, texts: Vec<String>) -> JobInputs {
    let checks: Vec<_> = texts
        .into_iter()
        .map(|text| (parse_check(&text).expect("check"), text))
        .collect();
    let consent = json!({
        "tokenId": "7", "dataset": DATASET, "manifestCid": MANIFEST_CID, "plaintextHash": w.record.plaintext_hash.to_string(),
        "family": "tabular", "rulesVersion": "v12.0", "labelHash": label_hash,
        "checkHashes": checks.iter().map(|(p, _)| p.hash.to_string()).collect::<Vec<_>>(),
        "workloadIdentity": WORKLOAD, "jobId": JOB,
        "minBootloaderSvn": 10, "minTeeSvn": 0, "minSnpSvn": 23, "minMicrocodeSvn": 84, "expiresAt": "1795556000",
    });
    JobInputs {
        kind: JobKind::Threshold,
        consent,
        consent_signature: "0x00".to_owned(),
        token_id: "7".to_owned(),
        dataset: DATASET.to_owned(),
        manifest_cid: MANIFEST_CID.to_owned(),
        family: "tabular".to_owned(),
        checks: checks
            .into_iter()
            .map(|(parsed, check_json)| CheckSpec {
                check_hash: parsed.hash,
                check_json,
                conditions: parsed.conditions,
                allowed_failure_permille: parsed.allowed_failure_permille,
            })
            .collect(),
        encrypted_label: Some(envelope.to_owned()),
    }
}

fn wide_text() -> String {
    json!({"conditions": [{"column": "amount", "min": "10", "max": "60"}], "allowed_failure_permille": 100}).to_string()
}

fn narrow_text() -> String {
    json!({"conditions": [{"column": "id", "min": "1000", "max": "1002"}], "allowed_failure_permille": 100}).to_string()
}

fn threshold_world() -> (World, JobInputs) {
    let w = world();
    let module = engine();
    let mut appraisal = module
        .appraisal(
            "comma-clean.csv",
            "csv",
            Some(&"ab".repeat(32)),
            Some(MANIFEST_CID),
        )
        .expect("start");
    loop {
        appraisal.feed(&w.plain).expect("feed");
        if !appraisal.next_pass().expect("pass") {
            break;
        }
    }
    let output: Value = serde_json::from_str(&appraisal.finish().expect("finish")).expect("json");
    let label = serde_json::to_string(&output["label"]).expect("label");
    let label_hash = module.label_hash(&label).expect("hash");
    let envelope = seal_label(&label, &KEY).expect("seal");
    let (wide, narrow) = (wide_text(), narrow_text());
    let inputs = threshold_inputs(&w, &label_hash, &envelope, vec![wide, narrow]);
    (w, inputs)
}

/// A threshold job posts one signed result per check, in order: an answer with a proof and a refusal for a group too small.
#[test]
fn a_threshold_job_posts_a_signed_result_per_check() {
    let (w, inputs) = threshold_world();
    assert_eq!(run(&w, Ok(inputs), |_| {}), Ok(()));
    let posted = w.posted.lock().expect("lock").clone();
    assert_eq!(posted.len(), 1);
    let body = &posted[0];
    assert_eq!(body["kind"], "threshold");
    let results = body["results"].as_array().expect("results");
    assert_eq!(results.len(), 2);
    let (answered, refused) = (&results[0]["result"], &results[1]["result"]);
    assert_eq!(
        (answered["checkHash"].as_str(), answered["status"].as_str()),
        (
            Some(
                parse_check(&wide_text())
                    .expect("check")
                    .hash
                    .to_string()
                    .as_str()
            ),
            Some("answered")
        )
    );
    assert_eq!(answered["circuitName"], "threshold_r2_c1");
    assert!(answered["band"].is_u64() && answered["passed"].is_boolean());
    assert_eq!(
        (
            refused["checkHash"].as_str(),
            refused["status"].as_str(),
            refused["reason"].as_str()
        ),
        (
            Some(
                parse_check(&narrow_text())
                    .expect("check")
                    .hash
                    .to_string()
                    .as_str()
            ),
            Some("refused"),
            Some("small_group")
        )
    );
    assert!(posted_signature_verifies(body, answered) && posted_signature_verifies(body, refused));
    assert_eq!(*w.proved.lock().expect("lock"), ["threshold_r2_c1"]);
    assert_eq!(
        w.released.lock().expect("lock").len(),
        1,
        "one key release serves every check"
    );
}

/// The metrics object of a posted body: exactly the agreed keys, every value an integer of at most 2^53, and a signature of
/// its own under the result key.
fn checked_metrics(body: &Value) -> Value {
    let metrics = body["metrics"].clone();
    let keys = |v: &Value| -> Vec<String> {
        let mut keys: Vec<String> = v.as_object().expect("object").keys().cloned().collect();
        keys.sort();
        keys
    };
    assert_eq!(
        keys(&metrics),
        [
            "diskPeakBytes",
            "enginePeakBytes",
            "fetch",
            "passes",
            "proofs",
            "rssPeakBytes",
            "stageMs",
            "tokenRefreshes",
            "v",
            "wallMs"
        ]
    );
    assert_eq!(
        keys(&metrics["stageMs"]),
        ["checks", "claim", "job", "key", "post", "prove", "wait"]
    );
    assert_eq!(
        keys(&metrics["fetch"]),
        ["busyMs", "bytes", "chunks", "wallMs"]
    );
    for pass in metrics["passes"].as_array().expect("passes") {
        assert_eq!(
            keys(pass),
            ["chunks", "decompressMs", "decryptMs", "parseMs", "waitMs"]
        );
    }
    fn integers(value: &Value) {
        match value {
            Value::Number(n) => assert!(n.as_u64().is_some_and(|n| n < 1 << 53), "{n}"),
            Value::Array(items) => items.iter().for_each(integers),
            Value::Object(map) => map.values().for_each(integers),
            other => panic!("not an integer: {other}"),
        }
    }
    integers(&metrics);
    assert_eq!(metrics["v"], 1);
    let runtime: Value = serde_json::from_slice(
        &STANDARD
            .decode(body["runtimeData"].as_str().expect("runtime"))
            .expect("b64"),
    )
    .expect("json");
    let signature: [u8; 65] = hex::decode(
        body["metricsSignature"]
            .as_str()
            .expect("metricsSignature")
            .trim_start_matches("0x"),
    )
    .expect("hex")
    .try_into()
    .expect("65 bytes");
    assert_eq!(
        verify_result_signature(
            runtime["resultPublicKey"].as_str().expect("key"),
            &result_digest(&metrics).expect("digest"),
            &signature,
        ),
        Ok(true),
        "the metrics are signed with the result key"
    );
    metrics
}

/// An appraisal job posts what it cost beside its result, signed as an object of its own: the chunks and bytes fetched, a
/// pass over every chunk, one proof, a token for the key release and one for the post, and the engine's memory.
#[test]
fn an_appraisal_job_posts_its_metrics_signed() {
    let w = world();
    assert_eq!(run(&w, Ok(appraisal_inputs(&w)), |_| {}), Ok(()));
    let posted = w.posted.lock().expect("lock").clone();
    let body = &posted[0];
    let metrics = checked_metrics(body);
    let manifest = Manifest::parse(&w.manifest_text).expect("manifest");
    let chunk_bytes: u64 = w
        .blobs
        .iter()
        .filter(|(cid, _)| cid.starts_with("QmChunk"))
        .map(|(_, bytes)| bytes.len() as u64)
        .sum();
    assert_eq!(metrics["fetch"]["chunks"], manifest.chunks.len());
    assert_eq!(metrics["fetch"]["bytes"], chunk_bytes);
    assert_eq!(metrics["diskPeakBytes"], chunk_bytes);
    let passes = metrics["passes"].as_array().expect("passes");
    assert!(!passes.is_empty());
    for pass in passes {
        assert_eq!(pass["chunks"], manifest.chunks.len());
    }
    assert_eq!(metrics["proofs"], 1);
    assert_eq!(
        metrics["tokenRefreshes"], 2,
        "one for the key release, one for the post"
    );
    assert!(metrics["enginePeakBytes"].as_u64().expect("peak") > 0);
    // The result is the same value as without metrics: its signature still verifies on its own
    assert!(posted_signature_verifies(body, &body["result"]));
}

/// A threshold job's metrics are one object for the whole job, and the results carry none of it.
#[test]
fn a_threshold_job_posts_one_metrics_object_for_all_its_checks() {
    let (w, inputs) = threshold_world();
    assert_eq!(run(&w, Ok(inputs), |_| {}), Ok(()));
    let posted = w.posted.lock().expect("lock").clone();
    let body = &posted[0];
    let metrics = checked_metrics(body);
    assert_eq!(
        metrics["proofs"].as_u64().expect("proofs"),
        w.proved.lock().expect("lock").len() as u64
    );
    for entry in body["results"].as_array().expect("results") {
        assert!(entry["result"].get("metrics").is_none());
    }
}

/// A failed job posts the metrics up to its failure: here the pass that found a chunk that does not authenticate.
#[test]
fn a_failed_job_posts_its_metrics_up_to_the_failure() {
    let mut w = world();
    w.blobs.get_mut("QmChunk1").expect("chunk")[3] ^= 1;
    assert_eq!(
        run(&w, Ok(appraisal_inputs(&w)), |_| {}),
        Err(ErrorCode::HashMismatch)
    );
    let posted = w.posted.lock().expect("lock").clone();
    let body = posted.last().expect("error body");
    assert_eq!(body["kind"], "error");
    let metrics = checked_metrics(body);
    assert_eq!(metrics["proofs"], 0);
    assert_eq!(
        metrics["passes"].as_array().expect("passes").len(),
        1,
        "the failing pass is in the record"
    );
    assert_eq!(metrics["passes"][0]["chunks"], 2);
}

fn posted_error(w: &World) -> Option<String> {
    let posted = w.posted.lock().expect("lock").clone();
    let body = posted.last()?;
    if body["kind"] != "error" {
        return None;
    }
    assert!(posted_signature_verifies(body, &body["result"]));
    assert_eq!(body["result"]["jobId"], JOB);
    Some(body["result"]["error"].as_str()?.to_owned())
}

/// Each failure stops the job with its code and posts that code, signed, as the only result.
#[test]
fn each_failure_posts_its_code_signed() {
    type Tweak = Box<dyn FnOnce(&mut Tweaks)>;
    let cases: Vec<(&str, ErrorCode, Tweak)> = vec![
        (
            "the decrypt action refuses",
            ErrorCode::KeyDenied,
            Box::new(|t| t.lit = Err(LitError::Denied)),
        ),
        (
            "Lit cannot be reached",
            ErrorCode::KeyDenied,
            Box::new(|t| t.lit = Err(LitError::Transport)),
        ),
        (
            "the prover fails",
            ErrorCode::ProveFailed,
            Box::new(|t| t.prove_fails = true),
        ),
        (
            "the registry holds another hash",
            ErrorCode::HashMismatch,
            Box::new(|t| t.record.plaintext_hash = Bytes32([0x42; 32])),
        ),
        (
            "the registry holds another manifest",
            ErrorCode::HashMismatch,
            Box::new(|t| t.record.manifest_cid = "QmOther".to_owned()),
        ),
        (
            "the result cannot be posted",
            ErrorCode::UploadFailed,
            Box::new(|t| t.post_fails = true),
        ),
    ];
    for (name, code, tweak) in cases {
        let w = world();
        assert_eq!(
            run(&w, Ok(appraisal_inputs(&w)), tweak),
            Err(code),
            "{name}"
        );
        if code != ErrorCode::UploadFailed {
            assert_eq!(posted_error(&w).as_deref(), Some(code.as_str()), "{name}");
        }
    }
}

/// Inputs that disagree with the consent or the claim are refused before any key is released.
#[test]
fn inputs_that_disagree_with_the_consent_are_refused_before_a_key_is_released() {
    type Mutation = Box<dyn Fn(&mut JobInputs)>;
    let mutations: Vec<(&str, Mutation)> = vec![
        ("another token", Box::new(|i| i.token_id = "8".to_owned())),
        (
            "another dataset",
            Box::new(|i| i.dataset = "other".to_owned()),
        ),
        (
            "another manifest",
            Box::new(|i| i.manifest_cid = "QmOther".to_owned()),
        ),
        ("another family", Box::new(|i| i.family = "text".to_owned())),
        (
            "a consent for another job",
            Box::new(|i| i.consent["jobId"] = json!(format!("0x{}", "11".repeat(32)))),
        ),
        (
            "a consent with an extra field",
            Box::new(|i| i.consent["extra"] = json!(1)),
        ),
    ];
    for (name, mutate) in mutations {
        let w = world();
        let mut inputs = appraisal_inputs(&w);
        mutate(&mut inputs);
        assert_eq!(
            run(&w, Ok(inputs), |_| {}),
            Err(ErrorCode::KeyDenied),
            "{name}"
        );
        assert!(
            w.released.lock().expect("lock").is_empty(),
            "{name}: a key was requested"
        );
    }
}

/// Tampered chunks, a missing chunk and an API that does not answer each stop the job with their code.
#[test]
fn bad_chunks_and_a_silent_api_stop_the_job() {
    let mut w = world();
    w.blobs.get_mut("QmChunk1").expect("chunk")[3] ^= 1;
    assert_eq!(
        run(&w, Ok(appraisal_inputs(&w)), |_| {}),
        Err(ErrorCode::HashMismatch)
    );
    assert_eq!(posted_error(&w).as_deref(), Some("hash_mismatch"));
    let mut w = world();
    w.blobs.remove("QmChunk2");
    assert_eq!(
        run(&w, Ok(appraisal_inputs(&w)), |_| {}),
        Err(ErrorCode::FetchFailed)
    );
    let w = world();
    assert_eq!(run(&w, Err(ApiError), |_| {}), Err(ErrorCode::FetchFailed));
    assert_eq!(posted_error(&w).as_deref(), Some("fetch_failed"));
    let w = world();
    assert!(Manifest::parse(&w.manifest_text).is_ok());
}

/// A disk too small for the dataset's ciphertext and the workload's reserve ends the job with `too_large` before any chunk
/// is fetched (the chunks are gone from the gateway here, so a fetch would be `fetch_failed`); a disk with exactly enough
/// room runs the job.
#[test]
fn a_disk_without_room_for_the_dataset_ends_the_job_before_any_fetch() {
    let manifest = Manifest::parse(&world().manifest_text).expect("manifest");
    let needed =
        manifest.chunks.len() as u64 * chunk_limit(manifest.chunk_size) + DISK_RESERVE_BYTES;

    let mut w = world();
    w.blobs.retain(|cid, _| !cid.starts_with("QmChunk"));
    assert_eq!(
        run(&w, Ok(appraisal_inputs(&w)), |t| t.disk_free =
            Some(needed - 1)),
        Err(ErrorCode::TooLarge)
    );
    assert_eq!(posted_error(&w).as_deref(), Some("too_large"));

    let w = world();
    assert_eq!(
        run(&w, Ok(appraisal_inputs(&w)), |t| t.disk_free = Some(needed)),
        Ok(())
    );
}

/// A refused claim ends the job before anything else is asked of anyone, and nothing is posted.
#[test]
fn a_refused_claim_ends_the_job_with_nothing_posted() {
    let w = world();
    assert_eq!(
        run(&w, Ok(appraisal_inputs(&w)), |t| t.claim =
            Err(ClaimError::NoJob)),
        Err(ErrorCode::ClaimFailed)
    );
    assert!(w.posted.lock().expect("lock").is_empty());
    assert!(w.released.lock().expect("lock").is_empty());
}

/// A manifest of another token or dataset than the consent names is refused as a hash mismatch, before a key is released.
#[test]
fn a_manifest_for_another_dataset_or_token_is_refused() {
    for (field, value) in [
        ("dataset", "fedcba9876543210fedcba9876543210"),
        ("tokenId", "8"),
    ] {
        let mut w = world();
        let mut manifest: Value = serde_json::from_str(&w.manifest_text).expect("manifest");
        manifest[field] = json!(value);
        w.blobs
            .insert(MANIFEST_CID.to_owned(), manifest.to_string().into_bytes());
        assert_eq!(
            run(&w, Ok(appraisal_inputs(&w)), |_| {}),
            Err(ErrorCode::HashMismatch),
            "{field}"
        );
        assert!(
            w.released.lock().expect("lock").is_empty(),
            "{field}: a key was requested"
        );
    }
}

/// Threshold checks the API lists in another order than the consent names them are refused.
#[test]
fn checks_in_another_order_than_the_consent_are_refused() {
    let (w, mut inputs) = threshold_world();
    inputs.checks.reverse();
    assert_eq!(run(&w, Ok(inputs), |_| {}), Err(ErrorCode::KeyDenied));
    assert!(w.released.lock().expect("lock").is_empty());
}

/// A check text that does not hash to the consent's hash, or counts that are not the check's own, is refused before a key
/// is released.
#[test]
fn checks_that_are_not_the_signed_checks_are_refused() {
    type Mutation = Box<dyn Fn(&mut JobInputs)>;
    let mutations: Vec<(&str, Mutation)> = vec![
        (
            "another check under the same hash",
            Box::new(|i| i.checks[0].check_json = narrow_text()),
        ),
        (
            "another hash for the same check",
            Box::new(|i| i.checks[0].check_hash = Bytes32([0x42; 32])),
        ),
        (
            "another number of conditions",
            Box::new(|i| i.checks[0].conditions = 2),
        ),
        (
            "another allowed failure",
            Box::new(|i| i.checks[0].allowed_failure_permille = 200),
        ),
        (
            "a check that is not a check",
            Box::new(|i| i.checks[0].check_json = "{}".to_owned()),
        ),
        ("a check dropped", Box::new(|i| drop(i.checks.pop()))),
    ];
    for (name, mutate) in mutations {
        let (w, mut inputs) = threshold_world();
        mutate(&mut inputs);
        assert_eq!(
            run(&w, Ok(inputs), |_| {}),
            Err(ErrorCode::KeyDenied),
            "{name}"
        );
        assert!(
            w.released.lock().expect("lock").is_empty(),
            "{name}: a key was requested"
        );
    }
}

/// A job that outlasts the API's token age still posts its result, and a failure after that still posts its error:
/// each call after the first carries a token minted just before it.
#[test]
fn a_job_longer_than_the_token_age_still_posts_its_result() {
    let w = world();
    assert_eq!(
        run(&w, Ok(appraisal_inputs(&w)), |t| t.token_max_age =
            Some(600)),
        Ok(())
    );
    let posted = w.posted.lock().expect("lock").clone();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0]["kind"], "appraisal");
    assert_eq!(posted[0]["token"], "1400.x.y");
    let released = w.released.lock().expect("lock").clone();
    assert_eq!(released[0]["token"], "700.x.y");
}

/// The error code of a failure after a long run is posted with a fresh token, so the API can fail the job.
#[test]
fn an_error_after_a_long_run_is_posted_with_a_fresh_token() {
    let w = world();
    let outcome = run(&w, Ok(appraisal_inputs(&w)), |t| {
        t.token_max_age = Some(600);
        t.prove_fails = true;
    });
    assert_eq!(outcome, Err(ErrorCode::ProveFailed));
    let posted = w.posted.lock().expect("lock").clone();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0]["kind"], "error");
    assert_eq!(posted[0]["token"], "1400.x.y");
}

/// Every fetch of a job is bounded: the manifest by its own limit and each chunk by the limit of the manifest's chunk size.
#[test]
fn every_fetch_of_a_job_has_a_limit() {
    let w = world();
    assert_eq!(run(&w, Ok(appraisal_inputs(&w)), |_| {}), Ok(()));
    let fetches = w.fetches.lock().expect("lock").clone();
    let manifest: Vec<_> = fetches
        .iter()
        .filter(|(cid, _)| cid == MANIFEST_CID)
        .collect();
    assert_eq!(manifest, [&(MANIFEST_CID.to_owned(), MAX_MANIFEST_BYTES)]);
    let chunks: Vec<_> = fetches
        .iter()
        .filter(|(cid, _)| cid != MANIFEST_CID)
        .collect();
    assert!(!chunks.is_empty());
    assert!(
        chunks.iter().all(|(_, max)| *max == chunk_limit(4096)),
        "{chunks:?}"
    );
}
