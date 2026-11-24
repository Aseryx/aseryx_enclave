//! The API client sends the claim as the contract says and maps each answer to a claim outcome.

mod common;

use aseryx_enclave_harness::api::ApiJobSource;
use aseryx_enclave_harness::claim::{ClaimError, JobSource};
use aseryx_enclave_harness::consent::Bytes32;
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
