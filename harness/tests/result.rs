//! The signed results have exactly the agreed fields, are canonical, and verify under the result key. The engine tests'
//! environment variables apply (`make test` sets them).

mod common;

use aseryx_enclave_harness::consent::{Bytes32, Uint256, result_digest};
use aseryx_enclave_harness::engine::NativeEngine;
use aseryx_enclave_harness::error_code::ErrorCode;
use aseryx_enclave_harness::keys::{ResultKey, verify_result_signature};
use aseryx_enclave_harness::label::seal_label_with_iv;
use aseryx_enclave_harness::result::{
    DisputeFacts, JobFacts, Proof, Refusal, ResultError, appraisal_result, classify_count,
    error_result, label_dispute_result, sign_result, threshold_answer, threshold_dispute_result,
    threshold_refusal,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const RULES_HASH: &str =
    "196377069280065456317493222910811677995390882464815658788936813714641954860";

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} is not set; run the tests with `make test`")),
    )
}

fn module() -> NativeEngine {
    common::native_engine()
}

fn golden() -> Vec<u8> {
    std::fs::read(env_path("ENCLAVE_TABULAR_FIXTURES").join("goldens/comma-clean.csv"))
        .expect("golden")
}

fn facts() -> JobFacts {
    JobFacts {
        job_id: Bytes32([0xd8; 32]),
        workload_identity: Bytes32([0xf6; 32]),
        family: "tabular".to_owned(),
        rules_version: "v12.0".to_owned(),
        token_id: "7".to_owned(),
        dataset: "0123456789abcdef0123456789abcdef".to_owned(),
        manifest_cid: "QmManifest".to_owned(),
        plaintext_hash: Bytes32(Sha256::digest(golden()).into()),
        engine_version: "0.16.1".to_owned(),
        engine_library_sha256: NativeEngine::library_sha256(),
    }
}

fn proof(signals: usize) -> Proof {
    Proof {
        text: r#"{"pi_a":["1"],"protocol":"groth16"}"#.to_owned(),
        public_signals: (0..signals).map(|n| n.to_string()).collect(),
    }
}

fn engine_output() -> String {
    let module = module();
    let mut run = module
        .appraisal(
            "comma-clean.csv",
            "csv",
            Some(&"ab".repeat(32)),
            Some("QmManifest"),
        )
        .expect("start");
    let plain = golden();
    loop {
        run.feed(&plain).expect("feed");
        if !run.next_pass().expect("pass") {
            return run.finish().expect("finish");
        }
    }
}

fn keys(value: &Value) -> Vec<&str> {
    let mut names: Vec<&str> = value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    names
}

/// An appraisal result has exactly the agreed fields and carries nothing of the plaintext label.
#[test]
fn an_appraisal_result_has_exactly_the_agreed_fields() {
    let engine = engine_output();
    let label_hash = serde_json::from_str::<Value>(&engine).expect("json")["hashes"]["label_hash"]
        .as_str()
        .expect("hash")
        .to_owned();
    let envelope = seal_label_with_iv("{\"salt\":\"x\"}", &[1; 32], [2; 12]);
    let result = appraisal_result(
        &facts(),
        RULES_HASH,
        &engine,
        "tabular_appraisal_r7",
        &proof(12),
        &envelope,
    )
    .expect("result");
    assert_eq!(
        keys(&result),
        [
            "circuitInputs",
            "circuitName",
            "dataset",
            "encryptedLabel",
            "engine",
            "engineLibrarySha256",
            "engineVersion",
            "family",
            "jobId",
            "kind",
            "labelHash",
            "manifestCid",
            "plaintextHash",
            "proof",
            "publicSignals",
            "qualityNotes",
            "rulesHash",
            "rulesVersion",
            "tokenId",
            "v",
            "workloadIdentity"
        ]
    );
    assert_eq!(
        (result["v"].as_u64(), result["kind"].as_str()),
        (Some(2), Some("appraisal"))
    );
    assert_eq!(result["labelHash"], label_hash.as_str());
    assert_eq!(result["encryptedLabel"], envelope.as_str());
    assert_eq!(
        result["engineLibrarySha256"],
        hex::encode(NativeEngine::library_sha256().0)
    );
    assert_eq!(result["engine"], "native");
    let counts: Value =
        serde_json::from_str(result["circuitInputs"].as_str().expect("text")).expect("counts");
    assert_eq!(
        counts
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "total_records",
            "structure_defects",
            "rows",
            "informative",
            "data_columns",
            "duplicates",
            "effective_rows",
            "defects_a",
            "worst_blanks_a",
            "worst_junk_a",
            "has_label_a",
            "conflicts_a"
        ]
    );
    assert_eq!(counts["total_records"], 300);
    assert!(
        !result.to_string().contains("salt"),
        "a label field leaked into the result"
    );
    assert!(result_digest(&result).is_ok());
}

/// Bytes that hash to something else than the registry's are refused, and so is a proof with the wrong signals.
#[test]
fn the_wrong_plaintext_or_signals_are_refused() {
    let engine = engine_output();
    let mut other = facts();
    other.plaintext_hash = Bytes32([0x11; 32]);
    assert_eq!(
        appraisal_result(&other, RULES_HASH, &engine, "c", &proof(12), "e"),
        Err(ResultError::PlaintextHash)
    );
    for signals in [0usize, 7, 11, 13] {
        assert_eq!(
            appraisal_result(&facts(), RULES_HASH, &engine, "c", &proof(signals), "e"),
            Err(ResultError::Signals(signals, 12))
        );
    }
}

/// Engine output missing a field or with the wrong type is refused with the field named.
#[test]
fn engine_output_without_what_the_result_needs_is_refused() {
    let engine: Value = serde_json::from_str(&engine_output()).expect("json");
    let cases = [
        (vec!["witness", "rows"], Value::Null, "witness count"),
        (vec!["witness", "has_label_a"], json!(-1), "witness count"),
        (vec!["quality", "flags"], json!("none"), "quality flags"),
        (vec!["quality", "flags"], json!([1]), "quality flag"),
        (vec!["hashes", "label_hash"], json!(5), "label hash"),
    ];
    for (path, value, named) in cases {
        let mut changed = engine.clone();
        changed[path[0]][path[1]] = value;
        let outcome = appraisal_result(
            &facts(),
            RULES_HASH,
            &changed.to_string(),
            "c",
            &proof(12),
            "e",
        );
        assert!(
            matches!(outcome, Err(ResultError::Engine(field)) if field == named),
            "{path:?}: {outcome:?}"
        );
    }
    assert!(matches!(
        appraisal_result(&facts(), RULES_HASH, "not json", "c", &proof(12), "e"),
        Err(ResultError::Engine("JSON"))
    ));
}

/// A counted check is an answer to prove or a refusal.
#[test]
fn a_count_is_an_answer_or_a_refusal() {
    let answerable =
        json!({"error": null, "answerable": true, "band": 2, "passed": true}).to_string();
    assert_eq!(classify_count(&answerable), Ok(Ok((2, true))));
    let small =
        json!({"error": null, "answerable": false, "band": null, "passed": null}).to_string();
    assert_eq!(classify_count(&small), Ok(Err(Refusal::SmallGroup)));
    let broken = json!({"error": "column amount is not numeric", "answerable": false}).to_string();
    assert_eq!(classify_count(&broken), Ok(Err(Refusal::UnusableCheck)));
    for bad in [
        "not json",
        r#"{"error":null}"#,
        r#"{"error":null,"answerable":true}"#,
        r#"{"error":null,"answerable":true,"band":1}"#,
    ] {
        assert!(classify_count(bad).is_err(), "{bad}");
    }
}

/// A threshold answer and a refusal have exactly the agreed fields.
#[test]
fn threshold_results_have_exactly_the_agreed_fields() {
    let check = Bytes32([0xa; 32]);
    let answer = threshold_answer(
        &facts(),
        "12345",
        &check,
        2,
        true,
        "threshold_r2_c1",
        &proof(7),
    )
    .expect("answer");
    assert_eq!(
        keys(&answer),
        [
            "band",
            "checkHash",
            "circuitName",
            "dataset",
            "engine",
            "engineLibrarySha256",
            "engineVersion",
            "family",
            "jobId",
            "kind",
            "labelHash",
            "manifestCid",
            "passed",
            "plaintextHash",
            "proof",
            "publicSignals",
            "rulesVersion",
            "status",
            "tokenId",
            "v",
            "workloadIdentity"
        ]
    );
    assert_eq!(
        (
            answer["status"].as_str(),
            answer["band"].as_u64(),
            answer["passed"].as_bool()
        ),
        (Some("answered"), Some(2), Some(true))
    );
    for signals in [0usize, 6, 8] {
        assert_eq!(
            threshold_answer(&facts(), "1", &check, 1, false, "c", &proof(signals)),
            Err(ResultError::Signals(signals, 7))
        );
    }
    for (refusal, reason) in [
        (Refusal::SmallGroup, "small_group"),
        (Refusal::UnusableCheck, "unusable_check"),
    ] {
        let refused = threshold_refusal(&facts(), "12345", &check, refusal);
        assert_eq!(
            keys(&refused),
            [
                "checkHash",
                "dataset",
                "engine",
                "engineLibrarySha256",
                "engineVersion",
                "family",
                "jobId",
                "kind",
                "labelHash",
                "manifestCid",
                "plaintextHash",
                "reason",
                "rulesVersion",
                "status",
                "tokenId",
                "v",
                "workloadIdentity"
            ]
        );
        assert_eq!(
            (refused["status"].as_str(), refused["reason"].as_str()),
            (Some("refused"), Some(reason))
        );
        assert!(result_digest(&refused).is_ok());
    }
}

/// An error result is the code and nothing else, for every code.
#[test]
fn an_error_result_is_the_code_and_nothing_else() {
    for code in ErrorCode::ALL {
        let result = error_result(&Bytes32([0xd8; 32]), code);
        assert_eq!(keys(&result), ["error", "jobId", "kind", "v"]);
        assert_eq!(result["error"], code.to_string());
        assert_eq!(result["kind"], "error");
    }
}

/// A signature verifies under the result key for its result only.
#[test]
fn a_signed_result_verifies_for_its_result_only() {
    let key = ResultKey::generate().expect("key");
    let result = error_result(&Bytes32([0xd8; 32]), ErrorCode::KeyDenied);
    let signature = sign_result(&result, &key).expect("signature");
    assert_eq!(signature.len(), 132);
    let bytes: [u8; 65] = hex::decode(&signature[2..])
        .expect("hex")
        .try_into()
        .expect("65 bytes");
    assert_eq!(
        verify_result_signature(
            &key.public_hex(),
            &result_digest(&result).expect("digest"),
            &bytes
        ),
        Ok(true)
    );
    let other = error_result(&Bytes32([0xd8; 32]), ErrorCode::FetchFailed);
    assert_eq!(
        verify_result_signature(
            &key.public_hex(),
            &result_digest(&other).expect("digest"),
            &bytes
        ),
        Ok(false)
    );
    assert!(matches!(
        sign_result(&json!({"bad_key": 1}), &key),
        Err(ResultError::Canonical(_))
    ));
}

/// Decimal strings round-trip through the 256-bit value, including its extremes.
#[test]
fn decimal_conversion_round_trips() {
    for text in [
        "0",
        "1",
        "9",
        "10",
        "255",
        "256",
        "4294967296",
        "1000000000000000000000000000000",
        "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    ] {
        assert_eq!(Uint256::parse(text).expect("parse").to_decimal(), text);
    }
}

fn dispute_facts() -> DisputeFacts {
    DisputeFacts {
        job_id: Bytes32([0xd8; 32]),
        dispute_id: "41".to_owned(),
        workload_identity: Bytes32([0xf6; 32]),
        family: "tabular".to_owned(),
        rules_version: "v12.0".to_owned(),
        token_id: "7".to_owned(),
        dataset: "0123456789abcdef0123456789abcdef".to_owned(),
        buyer: "0x1234567890abcdef1234567890abcdef12345678".to_owned(),
        evidence_hash: Bytes32([0xee; 32]),
        engine_version: "0.16.1".to_owned(),
        engine_library_sha256: NativeEngine::library_sha256(),
    }
}

/// A label dispute's result has exactly the agreed fields, the engine's hashes as given, and is canonical.
#[test]
fn a_label_dispute_result_has_exactly_the_agreed_fields() {
    let engine = json!({
        "plaintext_hash": "111", "label_hash": "222", "inputs_commitment": "333", "error": null,
    })
    .to_string();
    let result = label_dispute_result(&dispute_facts(), &engine).expect("result");
    assert_eq!(
        keys(&result),
        [
            "buyer",
            "disputeId",
            "disputeType",
            "engine",
            "engineLibrarySha256",
            "engineVersion",
            "error",
            "evidenceHash",
            "family",
            "inputsCommitment",
            "jobId",
            "kind",
            "labelHash",
            "dataset",
            "plaintextHash",
            "rulesVersion",
            "tokenId",
            "v",
            "workloadIdentity",
        ]
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    );
    assert_eq!(result["v"], 2);
    assert_eq!(result["kind"], "dispute");
    assert_eq!(result["disputeType"], "label_mismatch");
    assert_eq!(result["disputeId"], "41");
    assert_eq!(
        result["buyer"],
        "0x1234567890abcdef1234567890abcdef12345678"
    );
    assert_eq!(result["evidenceHash"], format!("0x{}", "ee".repeat(32)));
    assert_eq!(result["plaintextHash"], "111");
    assert_eq!(result["labelHash"], "222");
    assert_eq!(result["inputsCommitment"], "333");
    assert_eq!(result["error"], Value::Null);
    assert!(result_digest(&result).is_ok());
}

/// A label that the file does not give carries nulls and the engine's reason.
#[test]
fn a_label_dispute_that_cannot_be_reproduced_carries_the_reason() {
    let engine = json!({
        "plaintext_hash": "111", "label_hash": null, "inputs_commitment": null, "error": "the label's format",
    })
    .to_string();
    let result = label_dispute_result(&dispute_facts(), &engine).expect("result");
    assert_eq!(result["labelHash"], Value::Null);
    assert_eq!(result["inputsCommitment"], Value::Null);
    assert_eq!(result["error"], "the label's format");
    assert!(result_digest(&result).is_ok());
}

/// A threshold dispute's result has exactly the agreed fields; the band and pass are null when the check was not
/// answerable.
#[test]
fn a_threshold_dispute_result_has_exactly_the_agreed_fields() {
    let check = Bytes32([0xc1; 32]);
    let answered = json!({
        "plaintext_hash": "111", "band": 4, "passed": true, "answerable": true, "error": null,
    })
    .to_string();
    let result = threshold_dispute_result(&dispute_facts(), &check, &answered).expect("result");
    let mut expected = vec![
        "band",
        "buyer",
        "checkHash",
        "dataset",
        "disputeId",
        "disputeType",
        "engine",
        "engineLibrarySha256",
        "engineVersion",
        "error",
        "evidenceHash",
        "family",
        "jobId",
        "kind",
        "passed",
        "plaintextHash",
        "rulesVersion",
        "tokenId",
        "v",
        "workloadIdentity",
    ];
    expected.sort_unstable();
    assert_eq!(keys(&result), expected);
    assert_eq!(result["disputeType"], "false_threshold");
    assert_eq!(result["checkHash"], check.to_string());
    assert_eq!(
        (result["band"].as_u64(), result["passed"].as_bool()),
        (Some(4), Some(true))
    );
    assert_eq!(result["error"], Value::Null);
    let unanswerable = json!({
        "plaintext_hash": "111", "band": null, "passed": null, "answerable": false, "error": "too few rows",
    })
    .to_string();
    let result = threshold_dispute_result(&dispute_facts(), &check, &unanswerable).expect("result");
    assert_eq!(
        (&result["band"], &result["passed"]),
        (&Value::Null, &Value::Null)
    );
    assert_eq!(result["error"], "too few rows");
    assert!(result_digest(&result).is_ok());
}

/// Engine output without what a dispute result needs, or with a field of the wrong type, is refused.
#[test]
fn engine_output_a_dispute_result_cannot_use_is_refused() {
    let facts = dispute_facts();
    for bad in [
        "not json",
        "{}",
        r#"{"plaintext_hash": 1}"#,
        r#"{"plaintext_hash": "1", "label_hash": 2}"#,
        r#"{"plaintext_hash": "1", "label_hash": "2", "inputs_commitment": 3}"#,
        r#"{"plaintext_hash": "1", "label_hash": "2", "inputs_commitment": "3", "error": 4}"#,
        r#"{"plaintext_hash": "1", "label_hash": "2", "inputs_commitment": "3"}"#,
        r#"{"plaintext_hash": "1", "inputs_commitment": "3", "error": null}"#,
        r#"{"plaintext_hash": "1", "label_hash": "2", "error": null}"#,
    ] {
        assert!(
            matches!(
                label_dispute_result(&facts, bad),
                Err(ResultError::Engine(_))
            ),
            "{bad}"
        );
    }
    let check = Bytes32([1; 32]);
    for bad in [
        "not json",
        "{}",
        r#"{"plaintext_hash": 1, "band": null, "passed": null, "error": null}"#,
        r#"{"plaintext_hash": "1", "band": "4", "passed": null, "error": null}"#,
        r#"{"plaintext_hash": "1", "band": 4, "passed": "yes", "error": null}"#,
        r#"{"plaintext_hash": "1", "band": 4.5, "passed": true, "error": null}"#,
        r#"{"plaintext_hash": "1", "band": 4, "passed": true, "error": 5}"#,
        r#"{"plaintext_hash": "1", "band": 4, "passed": true}"#,
        r#"{"plaintext_hash": "1", "passed": true, "error": null}"#,
        r#"{"plaintext_hash": "1", "band": 4, "error": null}"#,
    ] {
        assert!(
            matches!(
                threshold_dispute_result(&facts, &check, bad),
                Err(ResultError::Engine(_))
            ),
            "{bad}"
        );
    }
}
