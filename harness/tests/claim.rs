//! The two-step claim: token 1 carries the keys, the API assigns a job, token 2 carries the keys and the job.

use aseryx_enclave_harness::attest::{AttestError, Attestor};
use aseryx_enclave_harness::claim::{ClaimError, JobSource, claim_job};
use aseryx_enclave_harness::consent::Bytes32;
use aseryx_enclave_harness::error_code::ErrorCode;
use aseryx_enclave_harness::runtime_data::RuntimeData;
use serde_json::Value;
use std::sync::Mutex;

const JOB: &str = "0xd828621b01841c9a5630937da5ffb06cf43417178bee1149d90b84ca148408fa";

/// Records the bytes it is asked to attest and fails on a chosen call.
struct Attestations {
    seen: Mutex<Vec<Vec<u8>>>,
    fail_on: Option<usize>,
}

impl Attestations {
    fn new(fail_on: Option<usize>) -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
            fail_on,
        }
    }
    fn seen(&self) -> Vec<Value> {
        self.seen
            .lock()
            .expect("lock")
            .iter()
            .map(|b| serde_json::from_slice(b).expect("json"))
            .collect()
    }
}

impl Attestor for Attestations {
    fn attest(&self, runtime_data: &RuntimeData) -> Result<String, AttestError> {
        let mut seen = self.seen.lock().expect("lock");
        seen.push(runtime_data.to_bytes());
        if Some(seen.len()) == self.fail_on {
            return Err(AttestError::Transport);
        }
        Ok(format!("token{}.x.y", seen.len()))
    }
}

/// Records what it is asked and answers with a fixed result.
struct Api {
    asked: Mutex<Vec<(String, u32)>>,
    answer: Result<Bytes32, ClaimError>,
}

impl JobSource for Api {
    fn claim(&self, token: &str, memory_gb: u32) -> Result<Bytes32, ClaimError> {
        self.asked
            .lock()
            .expect("lock")
            .push((token.to_owned(), memory_gb));
        self.answer
    }
}

fn api(answer: Result<Bytes32, ClaimError>) -> Api {
    Api {
        asked: Mutex::new(Vec::new()),
        answer,
    }
}

/// Token 1 carries the keys and no job; token 2 carries the same keys and the claimed job.
#[test]
fn token_one_carries_the_keys_and_token_two_adds_the_job() {
    let attestor = Attestations::new(None);
    let source = api(Ok(Bytes32::parse(JOB).expect("job")));
    let claimed = claim_job(&attestor, &source, 4).expect("claimed");
    let seen = attestor.seen();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].get("jobId").is_none());
    assert_eq!(seen[1]["jobId"], JOB);
    for field in ["v", "responsePublicKey", "resultPublicKey"] {
        assert_eq!(seen[0][field], seen[1][field], "{field}");
    }
    assert_eq!(
        seen[0]["responsePublicKey"],
        claimed.response_key.public_hex()
    );
    assert_eq!(seen[0]["resultPublicKey"], claimed.result_key.public_hex());
    assert_eq!(claimed.job_id.to_string(), JOB);
    assert_eq!(claimed.token, "token2.x.y");
    assert_eq!(
        claimed.runtime_data.to_bytes(),
        attestor.seen.lock().expect("lock")[1]
    );
}

/// The API sees token 1 and the memory, and only token 1.
#[test]
fn the_api_is_given_token_one_and_the_memory() {
    let source = api(Ok(Bytes32::parse(JOB).expect("job")));
    claim_job(&Attestations::new(None), &source, 11).expect("claimed");
    assert_eq!(
        *source.asked.lock().expect("lock"),
        vec![("token1.x.y".to_owned(), 11)]
    );
}

/// Every claim generates new keys.
#[test]
fn every_claim_uses_new_keys() {
    let source = api(Ok(Bytes32::parse(JOB).expect("job")));
    let a = claim_job(&Attestations::new(None), &source, 2).expect("claimed");
    let b = claim_job(&Attestations::new(None), &source, 2).expect("claimed");
    assert_ne!(a.response_key.public_hex(), b.response_key.public_hex());
    assert_ne!(a.result_key.public_hex(), b.result_key.public_hex());
}

/// A failed first attestation never reaches the API.
#[test]
fn a_failed_first_attestation_never_reaches_the_api() {
    let attestor = Attestations::new(Some(1));
    let source = api(Ok(Bytes32::parse(JOB).expect("job")));
    assert_eq!(
        claim_job(&attestor, &source, 2).err(),
        Some(ErrorCode::AttestationFailed)
    );
    assert!(source.asked.lock().expect("lock").is_empty());
    assert_eq!(attestor.seen().len(), 1);
}

/// A refused claim asks for no second token.
#[test]
fn a_refused_claim_asks_for_no_second_token() {
    for refusal in [ClaimError::Refused, ClaimError::Transport] {
        let attestor = Attestations::new(None);
        assert_eq!(
            claim_job(&attestor, &api(Err(refusal)), 2).err(),
            Some(ErrorCode::ClaimFailed)
        );
        assert_eq!(attestor.seen().len(), 1);
    }
}

/// A failed second attestation is an attestation failure after the job was claimed.
#[test]
fn a_failed_second_attestation_is_an_attestation_failure() {
    let attestor = Attestations::new(Some(2));
    let source = api(Ok(Bytes32::parse(JOB).expect("job")));
    assert_eq!(
        claim_job(&attestor, &source, 2).err(),
        Some(ErrorCode::AttestationFailed)
    );
    assert_eq!(source.asked.lock().expect("lock").len(), 1);
}
