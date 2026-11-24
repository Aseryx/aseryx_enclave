//! The consent digests and the result digest equal the ones `consent.mjs` computes, as ethers' `TypedDataEncoder`
//! produced them in the vendored vector.

use aseryx_enclave_harness::consent::{
    Address, AppraisalJob, Bytes32, ConsentError, DisputeJob, Domain, ThresholdAnswerApproval,
    ThresholdJob, Uint256, canonical_json, result_digest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VECTOR: &str = include_str!("fixtures/consent-vector.json");
const SOURCE: &str = include_str!("fixtures/SOURCE.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("the vector is JSON")
}

fn domain() -> Domain {
    let v = vector();
    let chain_id = v["domain"]["chainId"].as_u64().expect("chain id");
    let contract = Address::parse(v["domain"]["verifyingContract"].as_str().expect("contract"))
        .expect("address");
    Domain::new(chain_id, contract).expect("domain")
}

fn entry(type_name: &str) -> (Value, String) {
    let v = vector();
    let found = v["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|e| e["typeName"] == type_name)
        .unwrap_or_else(|| panic!("no vector for {type_name}"))
        .clone();
    (
        found["consent"].clone(),
        found["digest"].as_str().expect("digest").to_owned(),
    )
}

/// The vendored fixtures are the files `SOURCE.json` names, so a hand edit is caught.
#[test]
fn the_vendored_fixtures_match_their_recorded_hashes() {
    let source: Value = serde_json::from_str(SOURCE).expect("SOURCE.json");
    let files = source["files"].as_array().expect("files");
    assert_eq!(files.len(), 2);
    for entry in files {
        let name = entry["file"].as_str().expect("file");
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let content = std::fs::read(path).expect("fixture");
        assert_eq!(
            hex::encode(Sha256::digest(&content)),
            entry["sha256"].as_str().expect("sha256"),
            "{name}"
        );
    }
}

/// Every typed-data digest equals the one ethers computed.
#[test]
fn every_digest_equals_the_vector() {
    let d = domain();
    let (consent, digest) = entry("AppraisalJob");
    assert_eq!(
        serde_json::from_value::<AppraisalJob>(consent)
            .expect("parse")
            .digest(d)
            .to_string(),
        digest
    );
    let (consent, digest) = entry("ThresholdJob");
    let job: ThresholdJob = serde_json::from_value(consent).expect("parse");
    assert_eq!(job.check_hashes.as_slice().len(), 2);
    assert_eq!(job.digest(d).to_string(), digest);
    let (consent, digest) = entry("DisputeJob");
    assert_eq!(
        serde_json::from_value::<DisputeJob>(consent)
            .expect("parse")
            .digest(d)
            .to_string(),
        digest
    );
    let (consent, digest) = entry("ThresholdAnswerApproval");
    assert_eq!(
        serde_json::from_value::<ThresholdAnswerApproval>(consent)
            .expect("parse")
            .digest(d)
            .to_string(),
        digest
    );
}

/// The digest changes with the chain, the contract and each field.
#[test]
fn the_digest_depends_on_the_domain_and_the_fields() {
    let d = domain();
    let (consent, _) = entry("AppraisalJob");
    let base: AppraisalJob = serde_json::from_value(consent.clone()).expect("parse");
    let digest = base.digest(d);
    let other_chain = Domain::new(1, Address([0x5d; 20])).expect("domain");
    assert_ne!(base.digest(other_chain), digest);
    for (field, value) in [
        ("tokenId", json!("3")),
        ("dataset", json!("other")),
        ("manifestCid", json!("QmOther")),
        ("plaintextHash", json!(format!("0x{}", "11".repeat(32)))),
        ("family", json!("text")),
        ("rulesVersion", json!("v13.0")),
        ("workloadIdentity", json!(format!("0x{}", "22".repeat(32)))),
        ("jobId", json!(format!("0x{}", "33".repeat(32)))),
        ("expiresAt", json!("1795556001")),
    ] {
        let mut changed = consent.clone();
        changed[field] = value;
        let job: AppraisalJob = serde_json::from_value(changed).expect("parse");
        assert_ne!(job.digest(d), digest, "{field}");
    }
}

/// The result digest equals the one ethers computed over the canonical JSON.
#[test]
fn the_result_digest_equals_the_vector() {
    let v = vector();
    let result = &v["result"];
    assert_eq!(
        canonical_json(&result["value"]).expect("canonical"),
        result["canonical"].as_str().expect("text")
    );
    assert_eq!(
        result_digest(&result["value"]).expect("digest").to_string(),
        result["digest"].as_str().expect("digest")
    );
}

/// Canonical JSON refuses what `canonical` in protocol.mjs refuses and ignores key order.
#[test]
fn canonical_json_refuses_what_protocol_mjs_refuses() {
    assert_eq!(
        canonical_json(&json!({"b": [1, {"d": true, "c": null}], "a": "x"})).expect("ok"),
        r#"{"a":"x","b":[1,{"c":null,"d":true}]}"#
    );
    for bad in [
        json!(1.5),
        json!(9_007_199_254_740_992u64),
        json!(-9_007_199_254_740_992i64),
        json!({"a b": 1}),
        json!({"1a": 1}),
        json!({"": 1}),
        json!({"é": 1}),
    ] {
        assert!(
            matches!(canonical_json(&bad), Err(ConsentError::Canonical(_))),
            "{bad}"
        );
    }
    assert_eq!(
        canonical_json(&json!(9_007_199_254_740_991u64)).expect("max safe"),
        "9007199254740991"
    );
    assert_eq!(
        canonical_json(&json!(-9_007_199_254_740_991i64)).expect("min safe"),
        "-9007199254740991"
    );
    let deep = |levels: usize| (0..levels).fold(json!(1), |inner, _| json!([inner]));
    assert!(canonical_json(&deep(8)).is_ok());
    assert!(canonical_json(&deep(9)).is_err());
    assert_eq!(
        canonical_json(&json!("a\"b\\c\n\u{1}é")).expect("string"),
        r#""a\"b\\c\n\u0001é""#
    );
}

/// A consent has exactly the fields of its type.
#[test]
fn a_consent_needs_exactly_the_fields_of_its_type() {
    let (consent, _) = entry("AppraisalJob");
    let mut extra = consent.clone();
    extra["extra"] = json!(1);
    assert!(serde_json::from_value::<AppraisalJob>(extra).is_err());
    for field in consent.as_object().expect("object").keys() {
        let mut missing = consent.clone();
        missing.as_object_mut().expect("object").remove(field);
        assert!(
            serde_json::from_value::<AppraisalJob>(missing).is_err(),
            "{field}"
        );
    }
}

/// Malformed values are refused.
#[test]
fn malformed_values_are_refused() {
    let (consent, _) = entry("AppraisalJob");
    let refuse = |field: &str, value: Value| {
        let mut changed = consent.clone();
        changed[field] = value;
        assert!(
            serde_json::from_value::<AppraisalJob>(changed).is_err(),
            "{field}"
        );
    };
    for value in [
        json!("-1"),
        json!("01"),
        json!("1.5"),
        json!(""),
        json!("x"),
        json!(-1),
        json!(1.5),
        json!("1".repeat(79)),
    ] {
        refuse("tokenId", value);
    }
    for value in [
        json!("0x12"),
        json!("12".repeat(32)),
        json!(format!("0x{}", "zz".repeat(32))),
        json!(format!("0x{}", "11".repeat(33))),
        json!(5),
    ] {
        refuse("plaintextHash", value);
    }
    refuse("dataset", json!(""));
    refuse("dataset", json!("x".repeat(201)));
    refuse("manifestCid", json!("x".repeat(257)));
    refuse("family", json!("x".repeat(65)));
    assert!(Bytes32::parse(&format!("0x{}", "AB".repeat(32))).is_ok());
}

/// The largest uint256 is accepted and one more is refused.
#[test]
fn the_uint256_range_is_enforced() {
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let over = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    assert_eq!(Uint256::parse(max).expect("max").0, [0xff; 32]);
    assert_eq!(Uint256::parse(over), Err(ConsentError::Uint256));
    assert_eq!(Uint256::parse("0").expect("zero").0, [0; 32]);
}

/// A threshold job names between one and five checks.
#[test]
fn a_threshold_job_names_one_to_five_checks() {
    let (consent, _) = entry("ThresholdJob");
    let with = |count: usize| {
        let mut changed = consent.clone();
        changed["checkHashes"] = json!(
            (1..=count)
                .map(|n| format!("0x{}", format!("{n:x}").repeat(64)))
                .collect::<Vec<_>>()
        );
        serde_json::from_value::<ThresholdJob>(changed)
    };
    for count in [1, 2, 5] {
        assert!(with(count).is_ok(), "{count}");
    }
    for count in [0, 6] {
        assert!(with(count).is_err(), "{count}");
    }
}

/// A domain needs a non-zero chain id.
#[test]
fn a_domain_needs_a_chain_id() {
    assert_eq!(Domain::new(0, Address([0; 20])), Err(ConsentError::ChainId));
    assert_eq!(Address::parse("0x1234"), Err(ConsentError::Address));
    assert_eq!(
        Address::parse(&format!("0x{}", "g".repeat(40))),
        Err(ConsentError::Address)
    );
}
