//! The sidecar client sends the runtime data as the sidecar expects and refuses anything that is not a token.

use aseryx_enclave_harness::attest::{AttestError, Attestor, SidecarAttestor};
use aseryx_enclave_harness::runtime_data::RuntimeData;
use base64::Engine;
mod common;

use common::serve_once;
use serde_json::Value;
use std::net::TcpListener;

const MAA: &str = "sharedeus.eus.attest.azure.net";

fn data() -> RuntimeData {
    RuntimeData::claim(&"ab".repeat(32), &format!("02{}", "cd".repeat(32)))
}

/// The request is a JSON POST to /attest/maa with the endpoint and the runtime data in base64.
#[test]
fn the_request_names_the_endpoint_and_carries_the_runtime_data() {
    let (url, seen) = serve_once("200 OK", r#"{"token":"aaa.bbb.ccc"}"#);
    let token = SidecarAttestor::new(&format!("{url}/"), MAA)
        .attest(&data())
        .expect("token");
    assert_eq!(token, "aaa.bbb.ccc");
    let request = seen.join().expect("server");
    assert!(
        request.starts_with("POST /attest/maa HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains("content-type: application/json")
    );
    let body: Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).expect("body")).expect("json");
    assert_eq!(body["maa_endpoint"], MAA);
    let sent = base64::engine::general_purpose::STANDARD
        .decode(body["runtime_data"].as_str().expect("runtime_data"))
        .expect("base64");
    assert_eq!(sent, data().to_bytes());
    assert_eq!(body.as_object().expect("object").len(), 2);
}

/// A status other than 200 is refused with that status.
#[test]
fn a_status_other_than_200_is_refused() {
    for (status, code) in [
        ("500 Internal Server Error", 500),
        ("404 Not Found", 404),
        ("204 No Content", 204),
    ] {
        let (url, _server) = serve_once(status, r#"{"token":"aaa.bbb.ccc"}"#);
        assert_eq!(
            SidecarAttestor::new(&url, MAA).attest(&data()),
            Err(AttestError::Status(code)),
            "{status}"
        );
    }
}

/// An answer that is not a token is refused.
#[test]
fn an_answer_that_is_not_a_token_is_refused() {
    for body in [
        "",
        "not json",
        "{}",
        r#"{"token":""}"#,
        r#"{"token":"a.b"}"#,
        r#"{"token":"a..c"}"#,
        r#"{"token":"a.b.c.d"}"#,
        r#"{"token":7}"#,
        "[]",
    ] {
        let (url, _server) = serve_once("200 OK", body);
        assert_eq!(
            SidecarAttestor::new(&url, MAA).attest(&data()),
            Err(AttestError::Body),
            "{body}"
        );
    }
}

/// A sidecar that cannot be reached is a transport failure.
#[test]
fn an_unreachable_sidecar_is_a_transport_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    drop(listener);
    assert_eq!(
        SidecarAttestor::new(&url, MAA).attest(&data()),
        Err(AttestError::Transport)
    );
}
