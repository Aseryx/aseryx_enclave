//! The API client sends the claim as the contract says and maps each answer to a claim outcome.

mod common;

use aseryx_enclave_harness::api::{ApiClient, ApiJobSource};
use aseryx_enclave_harness::claim::{ClaimError, JobSource};
use aseryx_enclave_harness::consent::Bytes32;
use aseryx_enclave_harness::job::{ApiError, DisputeType, Job, JobApi, JobInputs, JobKind};
use aseryx_enclave_harness::runtime_data::RuntimeData;
use base64::Engine;
use common::serve_once;
use serde_json::Value;
use std::net::TcpListener;

const JOB: &str = "0xd828621b01841c9a5630937da5ffb06cf43417178bee1149d90b84ca148408fa";

fn data() -> RuntimeData {
    RuntimeData::claim(&"ab".repeat(32), &format!("02{}", "cd".repeat(32)))
}

/// The request is a JSON POST with the action, the token, the exact runtime data in base64 and the memory.
#[test]
fn the_request_carries_the_token_the_runtime_data_and_the_memory() {
    let (url, seen) = serve_once("200 OK", &format!(r#"{{"jobId":"{JOB}"}}"#));
    let job = ApiJobSource::new(&format!("{url}/attested-appraisal"))
        .claim("aaa.bbb.ccc", &data(), 4)
        .expect("job");
    assert_eq!(job, Bytes32::parse(JOB).expect("job id"));
    let request = seen.join().expect("server");
    assert!(
        request.starts_with("POST /attested-appraisal HTTP/1.1\r\n"),
        "{request}"
    );
    let body: Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).expect("body")).expect("json");
    assert_eq!(body["action"], "claim");
    assert_eq!(body["token"], "aaa.bbb.ccc");
    assert_eq!(body["memoryGb"], 4);
    let sent = base64::engine::general_purpose::STANDARD
        .decode(body["runtimeData"].as_str().expect("runtimeData"))
        .expect("base64");
    assert_eq!(sent, data().to_bytes());
    assert_eq!(body.as_object().expect("object").len(), 4);
}

/// Each status maps to its outcome: no job, a refusal, or a transport failure.
#[test]
fn each_status_maps_to_its_outcome() {
    let cases = [
        ("404 Not Found", r#"{"error":"no_job"}"#, ClaimError::NoJob),
        (
            "403 Forbidden",
            r#"{"error":"claim_refused"}"#,
            ClaimError::Refused,
        ),
        (
            "400 Bad Request",
            r#"{"error":"claim_refused"}"#,
            ClaimError::Refused,
        ),
        (
            "500 Internal Server Error",
            r#"{"error":"x"}"#,
            ClaimError::Transport,
        ),
        ("502 Bad Gateway", "", ClaimError::Transport),
        ("301 Moved Permanently", "", ClaimError::Transport),
    ];
    for (status, body, expected) in cases {
        let (url, _server) = serve_once(status, body);
        assert_eq!(
            ApiJobSource::new(&url).claim("a.b.c", &data(), 2),
            Err(expected),
            "{status}"
        );
    }
}

/// An answer that is not a job id is a transport failure, never a job.
#[test]
fn an_answer_that_is_not_a_job_id_is_not_a_job() {
    for body in [
        "",
        "not json",
        "{}",
        r#"{"jobId":"0x12"}"#,
        r#"{"jobId":7}"#,
        r#"{"jobId":"abc"}"#,
    ] {
        let (url, _server) = serve_once("200 OK", body);
        assert_eq!(
            ApiJobSource::new(&url).claim("a.b.c", &data(), 2),
            Err(ClaimError::Transport),
            "{body}"
        );
    }
}

/// An API that cannot be reached is a transport failure.
#[test]
fn an_unreachable_api_is_a_transport_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);
    assert_eq!(
        ApiJobSource::new(&url).claim("a.b.c", &data(), 2),
        Err(ClaimError::Transport)
    );
}

const INPUTS: &str = r#"{"jobId":"0x01","kind":"appraisal","consent":{"a":1},"consentSignature":"0xab","tokenId":"4",
    "dataset":"0123456789abcdef0123456789abcdef","manifestCid":"QmManifest","family":"tabular"}"#;

fn request_body(request: &str) -> Value {
    serde_json::from_str(request.split("\r\n\r\n").nth(1).expect("body")).expect("json")
}

/// The job request names the action, the token and the exact runtime data, and the answer is the job's inputs.
#[test]
fn the_job_request_carries_the_token_and_the_runtime_data() {
    let (url, seen) = serve_once("200 OK", INPUTS);
    let Job::Data(inputs) = ApiClient::new(&url)
        .job("a.b.c", "cnVudGltZQ==")
        .expect("inputs")
    else {
        panic!("a dataset job");
    };
    assert_eq!(inputs.kind, JobKind::Appraisal);
    assert_eq!(inputs.manifest_cid, "QmManifest");
    assert_eq!(inputs.dataset, "0123456789abcdef0123456789abcdef");
    let request = seen.join().expect("server");
    assert!(request.starts_with("POST / HTTP/1.1\r\n"), "{request}");
    let body = request_body(&request);
    assert_eq!(
        body,
        serde_json::json!({"action": "job", "token": "a.b.c", "runtimeData": "cnVudGltZQ=="})
    );
}

/// Any answer but 200 with a job body is no job.
#[test]
fn an_answer_that_is_not_a_job_is_an_error() {
    for (status, body) in [
        ("403 Forbidden", r#"{"error":"claim_refused"}"#),
        ("404 Not Found", r#"{"error":"x"}"#),
        ("500 Internal Server Error", ""),
        ("200 OK", ""),
        ("200 OK", "{}"),
        ("200 OK", r#"{"kind":"nonsense"}"#),
    ] {
        let (url, _server) = serve_once(status, body);
        assert_eq!(
            ApiClient::new(&url).job("a.b.c", "x"),
            Err(ApiError),
            "{status} {body}"
        );
    }
}

/// A result is posted exactly as given, and only a 200 accepts it.
#[test]
fn a_result_is_posted_as_given_and_only_200_accepts_it() {
    let body =
        serde_json::json!({"action": "result", "token": "a.b.c", "kind": "appraisal", "n": [1, 2]});
    let (url, seen) = serve_once("200 OK", r#"{"ok":true}"#);
    assert_eq!(ApiClient::new(&url).post_result(&body), Ok(()));
    assert_eq!(request_body(&seen.join().expect("server")), body);
    for status in [
        "400 Bad Request",
        "403 Forbidden",
        "500 Internal Server Error",
    ] {
        let (url, _server) = serve_once(status, r#"{"error":"x"}"#);
        assert_eq!(
            ApiClient::new(&url).post_result(&body),
            Err(ApiError),
            "{status}"
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let gone = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);
    assert_eq!(ApiClient::new(&gone).post_result(&body), Err(ApiError));
    assert_eq!(ApiClient::new(&gone).job("a.b.c", "x"), Err(ApiError));
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture")
}

/// The API's job response of each kind, written by the API's own tests, parses as the job inputs: an appraisal job with
/// no checks, and a threshold job whose checks carry the hash, the JSON and the count the container reads.
#[test]
fn the_apis_job_responses_parse_as_job_inputs() {
    let appraisal: JobInputs =
        serde_json::from_str(&fixture("job-response-appraisal.json")).expect("appraisal");
    assert_eq!(appraisal.kind, JobKind::Appraisal);
    assert!(appraisal.checks.is_empty());
    assert_eq!(appraisal.encrypted_label, None);
    let threshold: JobInputs =
        serde_json::from_str(&fixture("job-response-threshold.json")).expect("threshold");
    assert_eq!(threshold.kind, JobKind::Threshold);
    assert_eq!(threshold.checks.len(), 1);
    let check = &threshold.checks[0];
    assert_eq!(check.check_hash, Bytes32([0xc1; 32]));
    assert_eq!(check.conditions, 1);
    assert_eq!(check.allowed_failure_permille, 0);
    let parsed = aseryx_enclave_harness::check::parse_check(&check.check_json).expect("check json");
    assert_eq!(parsed.conditions, check.conditions);
    assert_eq!(
        parsed.allowed_failure_permille,
        check.allowed_failure_permille
    );
    assert!(threshold.encrypted_label.is_some());
    assert_eq!(threshold.dataset, "0123456789abcdef0123456789abcdef");
}

/// A dispute job parses as a dispute, with its evidence and, for a threshold dispute, its check; anything else with a
/// kind of its own is a dataset job.
#[test]
fn a_dispute_response_parses_as_a_dispute_job() {
    let base = serde_json::json!({
        "jobId": JOB_ID, "kind": "dispute", "family": "tabular", "consent": {"disputeId": "41"},
        "consentSignature": "0xab", "disputeId": "41", "disputeType": "label_mismatch", "tokenId": "7",
        "dataset": "0123456789abcdef0123456789abcdef", "buyer": "0x1234567890abcdef1234567890abcdef12345678",
        "evidenceSealed": {"format": "aseryx-sealed-evidence-key-v1"},
        "evidence": {"manifestUrl": "https://s/m", "chunkUrls": ["https://s/0", "https://s/1"], "labelUrl": "https://s/l", "expiresAt": "2026-11-25T02:00:00Z"},
        "licenceLabelHash": "12345",
    });
    let Job::Dispute(label) = serde_json::from_value::<Job>(base.clone()).expect("dispute") else {
        panic!("a dispute");
    };
    assert_eq!(label.dispute_type, DisputeType::LabelMismatch);
    assert_eq!(label.evidence.chunk_urls.len(), 2);
    assert_eq!(label.licence_label_hash, "12345");
    assert_eq!(label.check, None);
    let mut threshold = base;
    threshold["disputeType"] = serde_json::json!("false_threshold");
    threshold["check"] = serde_json::json!({
        "checkHash": format!("0x{}", "c1".repeat(32)),
        "conditions": [{"column": "age", "min": "1"}],
        "allowedFailurePermille": 50, "stepPermille": 5,
    });
    let Job::Dispute(with_check) = serde_json::from_value::<Job>(threshold).expect("dispute")
    else {
        panic!("a dispute");
    };
    assert_eq!(with_check.dispute_type, DisputeType::FalseThreshold);
    assert_eq!(
        with_check.check.expect("check").allowed_failure_permille,
        50
    );
    // Not a dispute: a kind that is not one of the three, and a dispute missing its evidence
    assert!(serde_json::from_str::<Job>(r#"{"kind": "nonsense"}"#).is_err());
    assert!(serde_json::from_str::<Job>(r#"{"kind": "dispute"}"#).is_err());
    assert!(serde_json::from_str::<Job>("[]").is_err());
}

const JOB_ID: &str = "0xd828621b01841c9a5630937da5ffb06cf43417178bee1149d90b84ca148408fa";

/// The API's dispute job responses, written by the API's own tests, parse as dispute inputs: a label dispute with no check
/// and a threshold dispute whose check names the hash, the conditions and the failure share the engine counts with.
#[test]
fn the_apis_dispute_job_responses_parse_as_dispute_inputs() {
    let Job::Dispute(label) =
        serde_json::from_str::<Job>(&fixture("job-response-dispute-label.json")).expect("label")
    else {
        panic!("a dispute");
    };
    assert_eq!(label.dispute_type, DisputeType::LabelMismatch);
    assert_eq!(label.check, None);
    assert_eq!(label.dispute_id, "41");
    assert_eq!(label.dataset, "0123456789abcdef0123456789abcdef");
    assert_eq!(label.licence_label_hash, "777");
    assert_eq!(label.evidence.chunk_urls.len(), 3);
    assert!(label.evidence.manifest_url.starts_with("https://"));
    assert!(label.evidence.label_url.starts_with("https://"));
    assert_eq!(
        label.evidence_sealed["format"],
        "aseryx-sealed-evidence-key-v1"
    );
    let Job::Dispute(threshold) =
        serde_json::from_str::<Job>(&fixture("job-response-dispute-threshold.json"))
            .expect("threshold")
    else {
        panic!("a dispute");
    };
    assert_eq!(threshold.dispute_type, DisputeType::FalseThreshold);
    let check = threshold.check.expect("a check");
    assert_eq!(check.allowed_failure_permille, 50);
    assert!(check.conditions.is_array());
    // The consent in the response is the DisputeJob the buyer signed and parses as one
    let consent: aseryx_enclave_harness::consent::DisputeJob =
        serde_json::from_value(threshold.consent).expect("consent");
    assert_eq!(consent.dispute_id.to_decimal(), threshold.dispute_id);
    assert_eq!(consent.dataset.as_str(), threshold.dataset);
}
