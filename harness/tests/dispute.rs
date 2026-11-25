//! A dispute job end to end against stubs: the evidence key is released by the action, never a dataset key; the evidence
//! file and label are checked against the consent and the licence; the engine's finding is signed and posted.
//! The engine tests' environment variables apply (`make test` sets them).

mod common;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use aseryx_enclave_harness::attest::{AttestError, Attestor};
use aseryx_enclave_harness::chain::{ChainError, ChainReader, DatasetRecord};
use aseryx_enclave_harness::check::parse_check;
use aseryx_enclave_harness::claim::{ClaimError, JobSource};
use aseryx_enclave_harness::consent::{
    Address, Bytes32, DisputeJob, Domain, Uint256, result_digest,
};
use aseryx_enclave_harness::engine::{EngineModule, Limits};
use aseryx_enclave_harness::error_code::ErrorCode;
use aseryx_enclave_harness::job::{
    ApiError, DisputeCheck, DisputeInputs, DisputeType, Evidence, Job, JobApi, ProveError, Prover,
    Services, run_job,
};
use aseryx_enclave_harness::keys::verify_result_signature;
use aseryx_enclave_harness::label::seal_label;
use aseryx_enclave_harness::lit::{KeyReleaser, LitError, SealedResponse};
use aseryx_enclave_harness::result::{Proof, classify_count};
use aseryx_enclave_harness::runtime_data::RuntimeData;
use aseryx_enclave_harness::store::{CipherCache, Fetcher, StoreError, UrlFetcher};
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
use std::time::Duration;

const PINNED: &str = "0xc4565b13e634c8c900a7d241ed141974e93eb6fb895e0b016a63cce36d35968c";
const EVIDENCE_KEY: [u8; 32] = [9; 32];
const JOB: &str = "0xd828621b01841c9a5630937da5ffb06cf43417178bee1149d90b84ca148408fa";
const WORKLOAD: &str = "0xf6a7a4f67b3edf6d9d7c7098f9b514f53f263be0a4e32fbac2ee585d6972f20f";
const DATASET: &str = "0123456789abcdef0123456789abcdef";
const BUYER: &str = "0x1234567890abcdef1234567890abcdef12345678";
const CONTRACT: &str = "0x5Db410D07931Efc7CF1d01545e773992Ab1988b2";
const BASE: &str = "https://evidence.example";

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} is not set; run the tests with `make test`")),
    )
}

fn engine() -> EngineModule {
    let limits = Limits {
        deadline: Duration::from_secs(120),
        max_memory_bytes: 2 << 30,
    };
    let wasm = std::fs::read(env_path("ENCLAVE_ENGINE_WASM")).expect("engine module");
    EngineModule::load(&wasm, Bytes32::parse(PINNED).expect("pin"), limits).expect("loads")
}

fn golden(name: &str) -> Vec<u8> {
    std::fs::read(
        env_path("ENCLAVE_TABULAR_FIXTURES")
            .join("goldens")
            .join(name),
    )
    .expect("golden")
}

fn domain() -> Domain {
    Domain::new(43113, Address::parse(CONTRACT).expect("address")).expect("domain")
}

fn feed(mut run: aseryx_enclave_harness::engine::Run, plain: &[u8]) -> String {
    loop {
        run.feed(plain).expect("feed");
        if !run.next_pass().expect("pass") {
            return run.finish().expect("finish");
        }
    }
}

/// The label the engine writes for a file, its hash and its inputs commitment.
fn label_of(engine: &EngineModule, plain: &[u8]) -> (String, String, String) {
    let appraisal: Value = serde_json::from_str(&feed(
        engine
            .appraisal(
                "comma-clean.csv",
                "csv",
                Some(&"ab".repeat(32)),
                Some("QmManifest"),
            )
            .expect("start"),
        plain,
    ))
    .expect("json");
    let label = serde_json::to_string(&appraisal["label"]).expect("label");
    let hash = engine.label_hash(&label).expect("hash");
    (
        label,
        hash,
        appraisal["inputsCommitment"]
            .as_str()
            .expect("commitment")
            .to_owned(),
    )
}

/// The buyer's encrypted evidence: the file as a chunked manifest and the label as an envelope, under one key.
struct Delivered {
    evidence_hash: Bytes32,
    blobs: HashMap<String, Vec<u8>>,
    chunk_urls: Vec<String>,
}

fn evidence_of(plain: &[u8], label: &str) -> Delivered {
    let cipher = Aes256Gcm::new((&EVIDENCE_KEY).into());
    let (mut chunks, mut blobs, mut chunk_urls) = (Vec::new(), HashMap::new(), Vec::new());
    for (index, part) in plain.chunks(4096).enumerate() {
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(part).expect("gzip");
        let iv = [index as u8 + 1; 12];
        let sealed = cipher
            .encrypt(&Nonce::from(iv), gz.finish().expect("gzip").as_slice())
            .expect("encrypt");
        chunks.push(json!({"cid": format!("ipfs://QmEvidence{index}"), "iv": STANDARD.encode(iv)}));
        let url = format!("{BASE}/chunk/{index}");
        blobs.insert(url.clone(), sealed);
        chunk_urls.push(url);
    }
    let hash: [u8; 32] = Sha256::digest(plain).into();
    let manifest = json!({
        "version": "aseryx-hybrid-chipotle-v3", "totalSize": plain.len(), "chunkSize": 4096, "fileType": "csv",
        "plaintextSha256": hex::encode(hash), "uploadName": "delivered.csv", "tokenId": "7", "dataset": DATASET,
        "keyWrap": {"format": "aseryx-sealed-evidence-key-v1"}, "actionCid": "QmAction", "chunks": chunks,
    })
    .to_string();
    blobs.insert(format!("{BASE}/manifest"), manifest.into_bytes());
    blobs.insert(
        format!("{BASE}/label"),
        seal_label(label, &EVIDENCE_KEY)
            .expect("envelope")
            .into_bytes(),
    );
    Delivered {
        evidence_hash: Bytes32(hash),
        blobs,
        chunk_urls,
    }
}

fn consent(evidence_hash: &Bytes32) -> Value {
    json!({
        "disputeId": "41", "tokenId": "7", "dataset": DATASET, "buyer": BUYER,
        "evidenceHash": evidence_hash.to_string(), "family": "tabular", "rulesVersion": "v12.0",
        "workloadIdentity": WORKLOAD, "jobId": JOB,
        "minBootloaderSvn": 10, "minTeeSvn": 0, "minSnpSvn": 23, "minMicrocodeSvn": 84, "expiresAt": "1795556000",
    })
}

fn check_for(conditions: &Value, permille: u32) -> DisputeCheck {
    let text = json!({"conditions": conditions, "allowed_failure_permille": permille}).to_string();
    DisputeCheck {
        check_hash: parse_check(&text).expect("check").hash,
        conditions: conditions.clone(),
        allowed_failure_permille: permille,
    }
}

fn inputs(ev: &Delivered, label_hash: &str, kind: DisputeType) -> DisputeInputs {
    DisputeInputs {
        consent: consent(&ev.evidence_hash),
        consent_signature: "0x00".to_owned(),
        family: "tabular".to_owned(),
        dispute_id: "41".to_owned(),
        dispute_type: kind,
        token_id: "7".to_owned(),
        dataset: DATASET.to_owned(),
        buyer: BUYER.to_owned(),
        evidence_sealed: json!({"format": "aseryx-sealed-evidence-key-v1"}),
        evidence: Evidence {
            manifest_url: format!("{BASE}/manifest"),
            chunk_urls: ev.chunk_urls.clone(),
            label_url: format!("{BASE}/label"),
        },
        licence_label_hash: label_hash.to_owned(),
        check: (kind == DisputeType::FalseThreshold).then(|| {
            check_for(
                &json!([{"column": "amount", "min": "10", "max": "60"}]),
                100,
            )
        }),
    }
}

// ---- the stubs ----

struct Token;
impl Attestor for Token {
    fn attest(&self, _: &RuntimeData) -> Result<String, AttestError> {
        Ok("aaa.bbb.ccc".to_owned())
    }
}

struct Assigns;
impl JobSource for Assigns {
    fn claim(&self, _: &str, _: &RuntimeData, _: u32) -> Result<Bytes32, ClaimError> {
        Ok(Bytes32::parse(JOB).expect("job"))
    }
}

struct Api<'a> {
    job: Job,
    posted: &'a Mutex<Vec<Value>>,
}
impl JobApi for Api<'_> {
    fn job(&self, _: &str, _: &str) -> Result<Job, ApiError> {
        Ok(self.job.clone())
    }
    fn post_result(&self, body: &Value) -> Result<(), ApiError> {
        self.posted.lock().expect("lock").push(body.clone());
        Ok(())
    }
}

/// The relay stub: seals the evidence key, as the action does, to the response key in the runtime data, with the digest
/// of the buyer's consent as the HPKE info.
struct Lit<'a> {
    consent: Value,
    outcome: Result<(), LitError>,
    released: &'a Mutex<Vec<Value>>,
}
impl KeyReleaser for Lit<'_> {
    fn release(&self, request: &Value) -> Result<SealedResponse, LitError> {
        self.released.lock().expect("lock").push(request.clone());
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
        let digest = serde_json::from_value::<DisputeJob>(self.consent.clone())
            .expect("consent")
            .digest(domain());
        let info =
            format!(r#"{{"consent":"{digest}","domain":"aseryx/attested-key-response/v1"}}"#);
        let (encapped, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &public,
            info.as_bytes(),
            &EVIDENCE_KEY,
            &[],
        )
        .expect("seal");
        Ok(SealedResponse {
            enc: URL_SAFE_NO_PAD.encode(encapped.to_bytes()),
            ciphertext: URL_SAFE_NO_PAD.encode(ct),
        })
    }
}

/// A dispute reads nothing from the chain and nothing from IPFS, and proves nothing.
struct Unused;
impl ChainReader for Unused {
    fn get_dataset(&self, _: &Uint256, _: &str) -> Result<DatasetRecord, ChainError> {
        panic!("a dispute read the registry")
    }
}
impl Fetcher for Unused {
    fn fetch(&self, _: &str, _: u64) -> Result<Vec<u8>, StoreError> {
        panic!("a dispute fetched from IPFS")
    }
}
impl Prover for Unused {
    fn prove(&self, _: &str, _: &str) -> Result<Proof, ProveError> {
        panic!("a dispute made a proof")
    }
}

struct Urls(HashMap<String, Vec<u8>>);
impl UrlFetcher for Urls {
    fn get(&self, url: &str, _: u64) -> Result<Vec<u8>, StoreError> {
        self.0.get(url).cloned().ok_or(StoreError::Fetch)
    }
}

struct Run {
    outcome: Result<(), ErrorCode>,
    posted: Vec<Value>,
    released: Vec<Value>,
}

fn run(
    input: DisputeInputs,
    outcome_of_lit: Result<(), LitError>,
    blobs: HashMap<String, Vec<u8>>,
) -> Run {
    let (posted, released) = (Mutex::new(Vec::new()), Mutex::new(Vec::new()));
    let dir = unique_dir("dispute");
    let cache = CipherCache::new(&dir).expect("cache");
    let engine = engine();
    let lit = Lit {
        consent: input.consent.clone(),
        outcome: outcome_of_lit,
        released: &released,
    };
    let api = Api {
        job: Job::Dispute(Box::new(input)),
        posted: &posted,
    };
    let urls = Urls(blobs);
    let services = Services {
        attestor: &Token,
        source: &Assigns,
        api: &api,
        releaser: &lit,
        chain: &Unused,
        fetcher: &Unused,
        evidence: &urls,
        cache: &cache,
        engine: &engine,
        prover: &Unused,
        engine_module_sha256: Bytes32::parse(PINNED).expect("pin"),
        domain: domain(),
        memory_gb: 4,
        parallel_fetches: 3,
        appraisal_circuit: "tabular_appraisal_r7",
    };
    let outcome = run_job(&services);
    std::fs::remove_dir_all(dir).expect("cleanup");
    Run {
        outcome,
        posted: posted.into_inner().expect("lock"),
        released: released.into_inner().expect("lock"),
    }
}

fn signature_verifies(body: &Value) -> bool {
    let runtime: Value = serde_json::from_slice(
        &STANDARD
            .decode(body["runtimeData"].as_str().expect("runtime"))
            .expect("b64"),
    )
    .expect("json");
    let signature: [u8; 65] = hex::decode(
        body["signature"]
            .as_str()
            .expect("signature")
            .trim_start_matches("0x"),
    )
    .expect("hex")
    .try_into()
    .expect("65 bytes");
    verify_result_signature(
        runtime["resultPublicKey"].as_str().expect("key"),
        &result_digest(&body["result"]).expect("digest"),
        &signature,
    ) == Ok(true)
}

/// A world where the buyer's file and label are the licensed ones.
fn honest() -> (Delivered, String, String, String, Vec<u8>) {
    let engine = engine();
    let plain = golden("comma-clean.csv");
    let (label, hash, commitment) = label_of(&engine, &plain);
    (evidence_of(&plain, &label), label, hash, commitment, plain)
}

fn error_posted(run: &Run, code: ErrorCode) {
    assert_eq!(run.outcome, Err(code));
    assert_eq!(run.posted.len(), 1);
    let body = &run.posted[0];
    assert_eq!(body["kind"], "error");
    assert_eq!(body["result"]["error"], code.as_str());
    assert!(signature_verifies(body));
}

// ---- the results ----

/// A label dispute over the licensed file reproduces the label: the key released is the evidence key, nothing else is
/// asked of the action, and the signed result carries what the engine found.
#[test]
fn a_label_dispute_over_the_licensed_file_reproduces_the_label() {
    let (ev, _, hash, commitment, _) = honest();
    let input = inputs(&ev, &hash, DisputeType::LabelMismatch);
    let sealed = input.evidence_sealed.clone();
    let r = run(input, Ok(()), ev.blobs.clone());
    assert_eq!(r.outcome, Ok(()));
    assert_eq!(r.posted.len(), 1);
    let body = &r.posted[0];
    assert_eq!(
        (
            body["action"].as_str(),
            body["kind"].as_str(),
            body["token"].as_str()
        ),
        (Some("result"), Some("dispute"), Some("aaa.bbb.ccc"))
    );
    let result = &body["result"];
    assert_eq!(result["kind"], "dispute");
    assert_eq!(result["disputeType"], "label_mismatch");
    assert_eq!(result["jobId"], JOB);
    assert_eq!(result["disputeId"], "41");
    assert_eq!(result["buyer"], BUYER);
    assert_eq!(result["evidenceHash"], ev.evidence_hash.to_string());
    assert_eq!(result["labelHash"], hash);
    assert_eq!(result["inputsCommitment"], commitment);
    assert_eq!(result["error"], Value::Null);
    assert_eq!(result["workloadIdentity"], WORKLOAD);
    assert_eq!(
        result["engineModuleSha256"],
        PINNED.trim_start_matches("0x")
    );
    assert!(signature_verifies(body));
    assert_eq!(r.released.len(), 1);
    let mut names: Vec<&str> = r.released[0]
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["action", "evidenceSealed", "runtimeData", "token"]);
    assert_eq!(r.released[0]["evidenceSealed"], sealed);
}

/// Another file than the label was made from does not reproduce the label.
#[test]
fn a_label_dispute_over_another_file_does_not_reproduce_the_label() {
    let engine = engine();
    let licensed = golden("comma-clean.csv");
    let (label, hash, _) = label_of(&engine, &licensed);
    let delivered = golden("defects.csv");
    let ev = evidence_of(&delivered, &label);
    let r = run(
        inputs(&ev, &hash, DisputeType::LabelMismatch),
        Ok(()),
        ev.blobs.clone(),
    );
    assert_eq!(r.outcome, Ok(()));
    let result = &r.posted[0]["result"];
    assert_ne!(result["labelHash"], json!(hash), "{result}");
    assert!(signature_verifies(&r.posted[0]));
}

/// A threshold dispute reports the band and pass the disputed check gives on the evidence file.
#[test]
fn a_threshold_dispute_reports_the_band_and_pass_of_the_disputed_check() {
    let (ev, label, hash, _, plain) = honest();
    let input = inputs(&ev, &hash, DisputeType::FalseThreshold);
    let check = input.check.clone().expect("check");
    let engine = engine();
    let check_text =
        json!({"conditions": check.conditions, "allowed_failure_permille": 100}).to_string();
    let count = feed(
        engine.threshold_count(&label, &check_text).expect("start"),
        &plain,
    );
    let (band, passed) = classify_count(&count).expect("count").expect("answerable");
    let r = run(input, Ok(()), ev.blobs.clone());
    assert_eq!(r.outcome, Ok(()));
    let result = &r.posted[0]["result"];
    assert_eq!(result["disputeType"], "false_threshold");
    assert_eq!(result["checkHash"], check.check_hash.to_string());
    assert_eq!(result["band"], json!(band));
    assert_eq!(result["passed"], json!(passed));
    assert_eq!(result["error"], Value::Null);
    assert!(signature_verifies(&r.posted[0]));
    assert!(result.get("labelHash").is_none());
}

// ---- refusals ----

/// Evidence that is not the file the buyer consented to, or that does not decrypt, is `evidence_mismatch`.
#[test]
fn evidence_that_is_not_the_consented_file_is_refused() {
    let (ev, _, hash, _, _) = honest();
    let base = inputs(&ev, &hash, DisputeType::LabelMismatch);

    // The consent names another file than the manifest holds
    let mut input = base.clone();
    input.consent["evidenceHash"] = json!(format!("0x{}", "11".repeat(32)));
    error_posted(
        &run(input, Ok(()), ev.blobs.clone()),
        ErrorCode::EvidenceMismatch,
    );

    // A chunk that was changed after it was encrypted
    let mut blobs = ev.blobs.clone();
    blobs.get_mut(&format!("{BASE}/chunk/0")).expect("chunk")[0] ^= 1;
    error_posted(
        &run(base.clone(), Ok(()), blobs),
        ErrorCode::EvidenceMismatch,
    );

    // A manifest of another token, another dataset, or no manifest at all
    for (field, value) in [
        ("tokenId", "8"),
        ("dataset", "ffffffffffffffffffffffffffffffff"),
    ] {
        let mut blobs = ev.blobs.clone();
        let url = format!("{BASE}/manifest");
        let mut manifest: Value = serde_json::from_slice(&blobs[&url]).expect("manifest");
        manifest[field] = json!(value);
        blobs.insert(url, manifest.to_string().into_bytes());
        error_posted(
            &run(base.clone(), Ok(()), blobs),
            ErrorCode::EvidenceMismatch,
        );
    }
    let mut blobs = ev.blobs.clone();
    blobs.insert(format!("{BASE}/manifest"), b"not a manifest".to_vec());
    error_posted(&run(base, Ok(()), blobs), ErrorCode::EvidenceMismatch);
}

/// A label that is not the licence's, or that does not open, is `label_mismatch_evidence`, and so is a family the
/// engine does not run.
#[test]
fn a_label_that_is_not_the_licences_is_refused() {
    let (ev, _, hash, _, _) = honest();
    let base = inputs(&ev, &hash, DisputeType::LabelMismatch);

    let mut input = base.clone();
    input.licence_label_hash = "12345".to_owned();
    error_posted(
        &run(input, Ok(()), ev.blobs.clone()),
        ErrorCode::LabelMismatchEvidence,
    );

    let mut blobs = ev.blobs.clone();
    blobs.insert(
        format!("{BASE}/label"),
        seal_label("{}", &[1; 32]).expect("envelope").into_bytes(),
    );
    error_posted(
        &run(base.clone(), Ok(()), blobs),
        ErrorCode::LabelMismatchEvidence,
    );

    let mut blobs = ev.blobs.clone();
    blobs.insert(format!("{BASE}/label"), b"not an envelope".to_vec());
    error_posted(
        &run(base.clone(), Ok(()), blobs),
        ErrorCode::LabelMismatchEvidence,
    );

    let mut blobs = ev.blobs.clone();
    blobs.insert(format!("{BASE}/label"), vec![0xff, 0xfe]);
    error_posted(
        &run(base.clone(), Ok(()), blobs),
        ErrorCode::LabelMismatchEvidence,
    );

    let mut input = base;
    input.family = "other".to_owned();
    input.consent["family"] = json!("other");
    let r = run(input, Ok(()), ev.blobs.clone());
    error_posted(&r, ErrorCode::LabelMismatchEvidence);
    assert!(
        r.released.is_empty(),
        "no key is released for a family the engine does not run"
    );
}

/// A label of another family, with no family or with a family that is not a string is refused even when its hash is the
/// licence's, as the zk server's dispute checks refuse it.
#[test]
fn a_label_of_another_family_is_refused_even_with_the_licences_hash() {
    let engine = engine();
    let plain = golden("comma-clean.csv");
    let (label, _, _) = label_of(&engine, &plain);
    let mut tested = 0;
    for (what, edit) in [
        ("another family", Some(json!("other"))),
        ("a family that is not a string", Some(json!(7))),
        ("no family", None),
    ] {
        let mut changed: Value = serde_json::from_str(&label).expect("label");
        match &edit {
            Some(family) => changed["family"] = family.clone(),
            None => {
                changed.as_object_mut().expect("object").remove("family");
            }
        }
        let changed = changed.to_string();
        // Only a label the engine can hash reaches the family check with the licence's hash
        let Ok(hash) = engine.label_hash(&changed) else {
            continue;
        };
        tested += 1;
        let ev = evidence_of(&plain, &changed);
        let r = run(
            inputs(&ev, &hash, DisputeType::LabelMismatch),
            Ok(()),
            ev.blobs.clone(),
        );
        assert_eq!(r.outcome, Err(ErrorCode::LabelMismatchEvidence), "{what}");
        assert_eq!(
            r.posted[0]["result"]["error"], "label_mismatch_evidence",
            "{what}"
        );
    }
    assert!(tested > 0, "the engine hashed none of the changed labels");
}

/// Evidence that cannot be fetched is `fetch_failed`.
#[test]
fn evidence_that_cannot_be_fetched_is_a_fetch_failure() {
    let (ev, _, hash, _, _) = honest();
    let base = inputs(&ev, &hash, DisputeType::LabelMismatch);
    for gone in [
        format!("{BASE}/manifest"),
        format!("{BASE}/label"),
        format!("{BASE}/chunk/0"),
    ] {
        let mut blobs = ev.blobs.clone();
        blobs.remove(&gone);
        error_posted(&run(base.clone(), Ok(()), blobs), ErrorCode::FetchFailed);
    }
    let mut input = base.clone();
    input.evidence.chunk_urls.pop();
    error_posted(
        &run(input, Ok(()), ev.blobs.clone()),
        ErrorCode::FetchFailed,
    );
    let mut input = base;
    input.evidence.chunk_urls.push(format!("{BASE}/chunk/0"));
    error_posted(
        &run(input, Ok(()), ev.blobs.clone()),
        ErrorCode::FetchFailed,
    );
}

/// A dispute that disagrees with its consent, or is inconsistent, is refused before any key is released.
#[test]
fn a_dispute_that_disagrees_with_its_consent_is_refused_before_a_key_is_released() {
    let (ev, _, hash, _, _) = honest();
    let label_dispute = inputs(&ev, &hash, DisputeType::LabelMismatch);
    let threshold_dispute = inputs(&ev, &hash, DisputeType::FalseThreshold);
    let cases: Vec<(&str, DisputeInputs)> = vec![
        (
            "dispute id",
            DisputeInputs {
                dispute_id: "42".into(),
                ..label_dispute.clone()
            },
        ),
        (
            "token",
            DisputeInputs {
                token_id: "8".into(),
                ..label_dispute.clone()
            },
        ),
        (
            "dataset",
            DisputeInputs {
                dataset: "ffffffffffffffffffffffffffffffff".into(),
                ..label_dispute.clone()
            },
        ),
        (
            "buyer",
            DisputeInputs {
                buyer: "0x0000000000000000000000000000000000000001".into(),
                ..label_dispute.clone()
            },
        ),
        (
            "buyer text",
            DisputeInputs {
                buyer: "not an address".into(),
                ..label_dispute.clone()
            },
        ),
        (
            "consent family",
            DisputeInputs {
                consent: {
                    let mut consent = label_dispute.consent.clone();
                    consent["family"] = json!("other");
                    consent
                },
                ..label_dispute.clone()
            },
        ),
        (
            "consent shape",
            DisputeInputs {
                consent: json!({"disputeId": "41"}),
                ..label_dispute.clone()
            },
        ),
        (
            "a check on a label dispute",
            DisputeInputs {
                check: threshold_dispute.check.clone(),
                ..label_dispute.clone()
            },
        ),
        (
            "no check on a threshold dispute",
            DisputeInputs {
                check: None,
                ..threshold_dispute.clone()
            },
        ),
    ];
    for (label, input) in cases {
        let r = run(input, Ok(()), ev.blobs.clone());
        assert_eq!(r.outcome, Err(ErrorCode::KeyDenied), "{label}");
        assert!(r.released.is_empty(), "{label}: a key was asked for");
    }
    // The job id in the consent is not the claimed job
    let mut input = label_dispute;
    input.consent["jobId"] = json!(format!("0x{}", "22".repeat(32)));
    let r = run(input, Ok(()), ev.blobs.clone());
    assert_eq!(r.outcome, Err(ErrorCode::KeyDenied));
    assert!(r.released.is_empty());
}

/// A disputed check that is not the check the API named is refused after the key is released but before any count.
#[test]
fn a_disputed_check_that_does_not_hash_to_its_name_is_refused() {
    let (ev, _, hash, _, _) = honest();
    let mut input = inputs(&ev, &hash, DisputeType::FalseThreshold);
    input.check.as_mut().expect("check").check_hash = Bytes32([0x42; 32]);
    error_posted(&run(input, Ok(()), ev.blobs.clone()), ErrorCode::KeyDenied);
    let mut input = inputs(&ev, &hash, DisputeType::FalseThreshold);
    input
        .check
        .as_mut()
        .expect("check")
        .allowed_failure_permille = 7;
    error_posted(&run(input, Ok(()), ev.blobs.clone()), ErrorCode::KeyDenied);
}

/// A key the action refuses ends the job as `key_denied`, with the error posted and signed.
#[test]
fn a_refused_evidence_key_ends_the_job() {
    let (ev, _, hash, _, _) = honest();
    let r = run(
        inputs(&ev, &hash, DisputeType::LabelMismatch),
        Err(LitError::Denied),
        ev.blobs.clone(),
    );
    error_posted(&r, ErrorCode::KeyDenied);
    assert_eq!(r.released.len(), 1);
}
