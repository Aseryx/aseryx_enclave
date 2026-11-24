//! The consent digests and the result digest equal the ones `consent.mjs` computes, as ethers' `TypedDataEncoder`
//! produced them in the vendored vector.

use aseryx_enclave_harness::consent::{
    Address, AppraisalJob, Bytes32, ConsentError, DisputeJob, Domain, Tcb, ThresholdAnswerApproval,
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
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .expect("fixtures")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name != "SOURCE.json")
        .collect();
    let mut listed: Vec<String> = files
        .iter()
        .map(|e| e["file"].as_str().expect("file").to_owned())
        .collect();
    on_disk.sort();
    listed.sort();
    assert_eq!(on_disk, listed, "every fixture is recorded in SOURCE.json");
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
        ("minBootloaderSvn", json!(11)),
        ("minTeeSvn", json!(2)),
        ("minSnpSvn", json!(31)),
        ("minMicrocodeSvn", json!(92)),
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

/// The vectors carry non-trivial firmware minimums, and each minimum changes the digest.
#[test]
fn the_firmware_minimums_are_in_the_vectors_and_the_digest() {
    let d = domain();
    let (consent, _) = entry("AppraisalJob");
    let job: AppraisalJob = serde_json::from_value(consent.clone()).expect("parse");
    assert_eq!(
        job.min_tcb(),
        Tcb {
            bootloader: 10,
            tee: 0,
            snp: 30,
            microcode: 91
        }
    );
    let (threshold, _) = entry("ThresholdJob");
    assert_eq!(
        serde_json::from_value::<ThresholdJob>(threshold)
            .expect("parse")
            .min_tcb(),
        Tcb {
            bootloader: 7,
            tee: 1,
            snp: 23,
            microcode: u32::MAX
        }
    );
    let (dispute, _) = entry("DisputeJob");
    assert_eq!(
        serde_json::from_value::<DisputeJob>(dispute)
            .expect("parse")
            .min_tcb(),
        Tcb {
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0
        }
    );
    for field in [
        "minBootloaderSvn",
        "minTeeSvn",
        "minSnpSvn",
        "minMicrocodeSvn",
    ] {
        let mut changed = consent.clone();
        changed[field] = json!(changed[field].as_u64().expect("number") + 1);
        let other: AppraisalJob = serde_json::from_value(changed).expect("parse");
        assert_ne!(other.digest(d), job.digest(d), "{field}");
    }
}

/// A firmware minimum is a uint32, as a number or a decimal string, and never more.
#[test]
fn a_firmware_minimum_is_a_uint32() {
    let (consent, digest) = entry("AppraisalJob");
    for field in [
        "minBootloaderSvn",
        "minTeeSvn",
        "minSnpSvn",
        "minMicrocodeSvn",
    ] {
        for good in [
            json!(0),
            json!("0"),
            json!(4_294_967_295u64),
            json!("4294967295"),
            json!("91"),
        ] {
            let mut changed = consent.clone();
            changed[field] = good.clone();
            assert!(
                serde_json::from_value::<AppraisalJob>(changed).is_ok(),
                "{field}={good}"
            );
        }
        for bad in [
            json!(4_294_967_296u64),
            json!("4294967296"),
            json!(-1),
            json!("-1"),
            json!(1.5),
            json!("1.5"),
            json!("01"),
            json!(""),
            json!("x"),
            json!(null),
            json!(true),
        ] {
            let mut changed = consent.clone();
            changed[field] = bad.clone();
            assert!(
                serde_json::from_value::<AppraisalJob>(changed).is_err(),
                "{field}={bad}"
            );
        }
    }
    let mut as_string = consent.clone();
    as_string["minSnpSvn"] = json!("30");
    assert_eq!(
        serde_json::from_value::<AppraisalJob>(as_string)
            .expect("parse")
            .digest(domain())
            .to_string(),
        digest
    );
}

/// The effective minimum is the higher of the floor and the consent, per version.
#[test]
fn the_effective_minimum_is_the_higher_of_the_floor_and_the_consent() {
    let floor = Tcb {
        bootloader: 10,
        tee: 0,
        snp: 23,
        microcode: 84,
    };
    let below = Tcb {
        bootloader: 1,
        tee: 0,
        snp: 5,
        microcode: 50,
    };
    let above = Tcb {
        bootloader: 12,
        tee: 3,
        snp: 40,
        microcode: 120,
    };
    let mixed = Tcb {
        bootloader: 9,
        tee: 1,
        snp: 30,
        microcode: 10,
    };
    assert_eq!(below.at_least(floor), floor);
    assert_eq!(above.at_least(floor), above);
    assert_eq!(
        mixed.at_least(floor),
        Tcb {
            bootloader: 10,
            tee: 1,
            snp: 30,
            microcode: 84
        }
    );
}
