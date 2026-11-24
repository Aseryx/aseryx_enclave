//! The label envelope and the attested response are the ones the JavaScript side makes, and the Lit client forwards the
//! request and tells a refusal from a failure.

mod common;

use aseryx_enclave_harness::consent::Bytes32;
use aseryx_enclave_harness::keys::ResponseKey;
use aseryx_enclave_harness::label::{LabelError, open_label, seal_label, seal_label_with_iv};
use aseryx_enclave_harness::lit::{
    ChipotleReleaser, KeyReleaser, LitError, SealedResponse, open_attested_response,
};
use common::serve_many;
use serde_json::{Value, json};

const VECTORS: &str = include_str!("fixtures/enclave-vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors")
}

fn bytes32(text: &str) -> [u8; 32] {
    hex::decode(text)
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

/// The envelope the web application's code writes for a fixed IV is the one this code writes, and this code opens it.
#[test]
fn the_label_envelope_equals_the_one_javascript_makes() {
    let v = vectors();
    let e = &v["labelEnvelope"];
    let key = bytes32(e["datasetKey"].as_str().expect("key"));
    let iv: [u8; 12] = (200u8..212)
        .collect::<Vec<_>>()
        .try_into()
        .expect("12 bytes");
    let label = e["labelText"].as_str().expect("label");
    assert_eq!(
        seal_label_with_iv(label, &key, iv),
        e["envelope"].as_str().expect("envelope")
    );
    assert_eq!(
        open_label(e["envelope"].as_str().expect("envelope"), &key).as_deref(),
        Ok(label)
    );
}

/// A fresh seal uses a fresh IV, opens under its key only, and a changed envelope does not open.
#[test]
fn a_sealed_label_opens_only_under_its_key_and_unchanged() {
    let key = [9u8; 32];
    let a = seal_label("{\"rows\":1}", &key).expect("seal");
    let b = seal_label("{\"rows\":1}", &key).expect("seal");
    assert_ne!(a, b);
    assert_eq!(open_label(&a, &key).as_deref(), Ok("{\"rows\":1}"));
    assert_eq!(open_label(&a, &[8u8; 32]), Err(LabelError::Open));
    let altered = a.replacen("\"ct\":\"", "\"ct\":\"AAAA", 1);
    assert_eq!(open_label(&altered, &key), Err(LabelError::Open));
    for bad in [
        "",
        "{}",
        r#"{"v":2,"iv":"AAAAAAAAAAAAAAAA","ct":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        r#"{"v":1,"iv":"AAAA","ct":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        r#"{"v":1,"iv":"AAAAAAAAAAAAAAAA","ct":"AAAA"}"#,
        r#"{"v":1,"iv":"AAAAAAAAAAAAAAAA","ct":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","x":1}"#,
        "not json",
    ] {
        assert_eq!(open_label(bad, &key), Err(LabelError::Shape), "{bad}");
    }
}

fn vector_response() -> (ResponseKey, SealedResponse, Bytes32, [u8; 32]) {
    let v = vectors();
    let r = &v["attestedResponse"];
    let key = ResponseKey::from_ikm(&bytes32(r["ikm"].as_str().expect("ikm")));
    assert_eq!(
        key.public_hex(),
        r["responsePublicKey"].as_str().expect("public key")
    );
    let sealed: SealedResponse = serde_json::from_value(r["sealed"].clone()).expect("sealed");
    (
        key,
        sealed,
        Bytes32::parse(r["consentDigest"].as_str().expect("digest")).expect("digest"),
        bytes32(r["key"].as_str().expect("key")),
    )
}

/// A key sealed by the action's helper opens with the matching response key and the consent that released it.
#[test]
fn an_attested_response_sealed_by_javascript_opens_here() {
    let (key, sealed, digest, expected) = vector_response();
    assert_eq!(open_attested_response(&key, &sealed, &digest), Ok(expected));
}

/// It does not open with another response key, for another consent, or when changed.
#[test]
fn an_attested_response_opens_only_for_its_key_and_consent() {
    let (key, sealed, digest, _) = vector_response();
    assert_eq!(
        open_attested_response(&ResponseKey::generate().expect("key"), &sealed, &digest),
        Err(LitError::Open)
    );
    assert_eq!(
        open_attested_response(&key, &sealed, &Bytes32([1; 32])),
        Err(LitError::Open)
    );
    let mut altered = sealed.clone();
    altered.ciphertext.replace_range(
        0..1,
        if altered.ciphertext.starts_with('A') {
            "B"
        } else {
            "A"
        },
    );
    assert_eq!(
        open_attested_response(&key, &altered, &digest),
        Err(LitError::Open)
    );
    for bad in [
        SealedResponse {
            enc: String::new(),
            ciphertext: sealed.ciphertext.clone(),
        },
        SealedResponse {
            enc: "!!".to_owned(),
            ciphertext: sealed.ciphertext.clone(),
        },
        SealedResponse {
            enc: sealed.enc.clone(),
            ciphertext: "AAAA".to_owned(),
        },
    ] {
        assert_eq!(
            open_attested_response(&key, &bad, &digest),
            Err(LitError::Open)
        );
    }
}

fn sealed_json() -> Value {
    vectors()["attestedResponse"]["sealed"].clone()
}

/// The request names the action code and the parameters and carries the usage key; the sealed answer comes back.
#[test]
fn the_request_carries_the_code_the_parameters_and_the_usage_key() {
    let answer =
        json!({"has_error": false, "response": {"ok": true, "sealed": sealed_json()}}).to_string();
    let (url, seen) = serve_many(1, move |_| (200, answer.clone()));
    let params = json!({"operation": "attestedDecrypt", "kind": "appraisal"});
    let sealed = ChipotleReleaser::new(&url, "usage-key-123", "async function main(){}")
        .release(&params)
        .expect("sealed");
    assert_eq!(
        serde_json::to_value(&sealed.enc).expect("enc"),
        sealed_json()["enc"]
    );
    let body: Value = serde_json::from_str(&seen.join().expect("server")[0]).expect("json");
    assert_eq!(body["code"], "async function main(){}");
    assert_eq!(body["js_params"], params);
}

/// A refusal is a denial; everything else that is not a sealed key is a transport failure.
#[test]
fn a_refusal_is_a_denial_and_anything_else_is_a_failure() {
    let denied = json!({"has_error": false, "response": {"ok": false, "error": "access_denied"}})
        .to_string();
    let cases: Vec<(u16, String, LitError)> = vec![
        (200, denied, LitError::Denied),
        (
            200,
            json!({"has_error": true, "response": {"ok": false}}).to_string(),
            LitError::Transport,
        ),
        (
            200,
            json!({"has_error": false, "response": {"ok": true}}).to_string(),
            LitError::Transport,
        ),
        (
            200,
            json!({"has_error": false, "response": {"ok": false, "sealed": sealed_json()}})
                .to_string(),
            LitError::Transport,
        ),
        (
            200,
            json!({"has_error": false}).to_string(),
            LitError::Transport,
        ),
        (200, "not json".to_owned(), LitError::Transport),
        (402, "{}".to_owned(), LitError::Transport),
        (500, String::new(), LitError::Transport),
    ];
    for (status, body, expected) in cases {
        let (url, _server) = serve_many(1, move |_| (status, body.clone()));
        assert_eq!(
            ChipotleReleaser::new(&url, "k", "c")
                .release(&json!({}))
                .err(),
            Some(expected),
            "{status}"
        );
    }
}
