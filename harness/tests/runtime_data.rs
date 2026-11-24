//! The runtime data is the shape Azure returned intact in the spike, and the error codes are the plan's.

use aseryx_enclave_harness::consent::Bytes32;
use aseryx_enclave_harness::error_code::ErrorCode;
use aseryx_enclave_harness::runtime_data::RuntimeData;
use base64::Engine;
use serde_json::{Value, json};

const RESPONSE: &str = "fde2e8df71621f3842c6407be330dfce724ef29c0ad7429a5c6995aa3904f139";
const RESULT: &str = "02f650523848d098c23a4412f3247461f4f3f2474b617ae6dd1f0c9155a9bdcd11";
const JOB: &str = "0xd828621b01841c9a5630937da5ffb06cf43417178bee1149d90b84ca148408fa";
const SPIKE_BYTES: &str = r#"{"v":1,"jobId":"0xd828621b01841c9a5630937da5ffb06cf43417178bee1149d90b84ca148408fa","responsePublicKey":"fde2e8df71621f3842c6407be330dfce724ef29c0ad7429a5c6995aa3904f139","resultPublicKey":"02f650523848d098c23a4412f3247461f4f3f2474b617ae6dd1f0c9155a9bdcd11"}"#;

/// The bytes of token 2's runtime data are exactly the bytes attested in spike 0.4a.
#[test]
fn the_job_runtime_data_is_the_spike_shape_byte_for_byte() {
    let data = RuntimeData::claim(RESPONSE, RESULT).for_job(&Bytes32::parse(JOB).expect("job"));
    assert_eq!(
        String::from_utf8(data.to_bytes()).expect("utf8"),
        SPIKE_BYTES
    );
}

/// Token 1's runtime data names the keys and no job.
#[test]
fn the_claim_runtime_data_has_no_job() {
    let value: Value =
        serde_json::from_slice(&RuntimeData::claim(RESPONSE, RESULT).to_bytes()).expect("json");
    assert_eq!(
        value,
        json!({"v": 1, "responsePublicKey": RESPONSE, "resultPublicKey": RESULT})
    );
}

/// The sidecar takes the bytes as standard base64, and the same bytes come back.
#[test]
fn the_base64_form_decodes_to_the_same_bytes() {
    let data = RuntimeData::claim(RESPONSE, RESULT);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(data.to_base64())
        .expect("base64");
    assert_eq!(decoded, data.to_bytes());
}

/// The claim and the job runtime data are two different byte strings, so the two tokens attest different things.
#[test]
fn the_job_changes_the_attested_bytes() {
    let claim = RuntimeData::claim(RESPONSE, RESULT);
    let job = claim.for_job(&Bytes32::parse(JOB).expect("job"));
    assert_ne!(claim.to_bytes(), job.to_bytes());
    assert_ne!(job.for_job(&Bytes32([1; 32])).to_bytes(), job.to_bytes());
}

/// Every error code round-trips through its text and serde, and nothing else parses.
#[test]
fn error_codes_round_trip_and_unknown_text_is_refused() {
    assert_eq!(ErrorCode::ALL.len(), 9);
    for code in ErrorCode::ALL {
        assert_eq!(code.to_string().parse::<ErrorCode>(), Ok(code));
        assert_eq!(
            serde_json::to_string(&code).expect("serialize"),
            format!("\"{code}\"")
        );
        assert_eq!(
            serde_json::from_str::<ErrorCode>(&format!("\"{code}\"")).expect("deserialize"),
            code
        );
    }
    for bad in [
        "",
        "Key_Denied",
        "key-denied",
        "unknown",
        "x".repeat(500).as_str(),
    ] {
        assert!("".parse::<ErrorCode>().is_err());
        let error = bad.parse::<ErrorCode>().expect_err(bad);
        assert!(error.to_string().len() < 80);
    }
    assert!(serde_json::from_str::<ErrorCode>("\"bogus\"").is_err());
}
