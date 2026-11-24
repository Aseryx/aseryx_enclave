//! A threshold check hashes to what the web application, the API and the SDK compute, whatever order it is written in.

use aseryx_enclave_harness::check::{CheckError, parse_check};
use aseryx_enclave_harness::consent::Uint256;
use serde_json::{Value, json};

const VECTORS: &str = include_str!("fixtures/threshold-vectors.json");

/// Every shared vector's check hashes to its recorded field element.
#[test]
fn every_shared_vector_hashes_to_its_recorded_check_hash() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("vectors");
    let hashed: Vec<&Value> = vectors
        .iter()
        .filter(|v| v.get("check_hash").is_some())
        .collect();
    assert_eq!(hashed.len(), 13);
    for vector in hashed {
        let parsed = parse_check(&vector["check"].to_string()).expect("check");
        assert_eq!(
            Uint256(parsed.hash.0).to_decimal(),
            vector["check_hash"].as_str().expect("hash"),
            "{}",
            vector["name"]
        );
        assert_eq!(
            parsed.hash.0[0], 0,
            "a field element of 31 bytes is left-padded"
        );
    }
}

/// The order of conditions, of values and of keys does not change the hash; the content does.
#[test]
fn the_hash_ignores_order_and_follows_content() {
    let a = json!({"conditions": [{"column": "b", "min": "1"}, {"column": "a", "values": ["y", "x"]}], "allowed_failure_permille": 100});
    let b = json!({"allowed_failure_permille": 100, "conditions": [{"values": ["x", "y"], "column": "a"}, {"min": "1", "column": "b"}]});
    let (pa, pb) = (
        parse_check(&a.to_string()).expect("a"),
        parse_check(&b.to_string()).expect("b"),
    );
    assert_eq!(pa.hash, pb.hash);
    assert_eq!((pa.conditions, pa.allowed_failure_permille), (2, 100));
    for changed in [
        json!({"conditions": [{"column": "b", "min": "2"}, {"column": "a", "values": ["y", "x"]}], "allowed_failure_permille": 100}),
        json!({"conditions": [{"column": "b", "min": "1"}, {"column": "a", "values": ["y", "z"]}], "allowed_failure_permille": 100}),
        json!({"conditions": [{"column": "b", "min": "1"}, {"column": "a", "values": ["y", "x"]}], "allowed_failure_permille": 50}),
        json!({"conditions": [{"column": "b", "max": "1"}, {"column": "a", "values": ["y", "x"]}], "allowed_failure_permille": 100}),
        json!({"conditions": [{"column": "c", "min": "1"}, {"column": "a", "values": ["y", "x"]}], "allowed_failure_permille": 100}),
    ] {
        assert_ne!(
            parse_check(&changed.to_string()).expect("changed").hash,
            pa.hash,
            "{changed}"
        );
    }
}

/// Columns and values sort by UTF-16 code unit, not by byte or code point.
#[test]
fn sorting_follows_utf16_code_units() {
    let astral = "\u{1F600}";
    let high_bmp = "\u{FF5E}";
    let one = json!({"conditions": [{"column": astral, "min": "1"}, {"column": high_bmp, "min": "1"}], "allowed_failure_permille": 10});
    let two = json!({"conditions": [{"column": high_bmp, "min": "1"}, {"column": astral, "min": "1"}], "allowed_failure_permille": 10});
    assert_eq!(
        parse_check(&one.to_string()).expect("one").hash,
        parse_check(&two.to_string()).expect("two").hash
    );
    // U+1F600 is the surrogate pair D83D DE00, which sorts before U+FF5E, so the canonical text lists it first.
    let canonical = format!(
        "{{\"allowed_failure_permille\":10,\"conditions\":[{{\"column\":\"{astral}\",\"min\":\"1\"}},{{\"column\":\"{high_bmp}\",\"min\":\"1\"}}]}}"
    );
    let digest = <sha2::Sha256 as sha2::Digest>::digest(canonical.as_bytes());
    assert_eq!(
        &parse_check(&one.to_string()).expect("one").hash.0[1..],
        &digest[..31]
    );
}

/// Text that is not exactly a check is refused, and so is a check with no condition or more than five.
#[test]
fn checks_that_are_not_exactly_a_check_are_refused() {
    let one = json!({"column": "a", "min": "1"});
    for bad in [
        "not json".to_owned(),
        json!({}).to_string(),
        json!({"conditions": [one.clone()]}).to_string(),
        json!({"allowed_failure_permille": 1}).to_string(),
        json!({"conditions": [one.clone()], "allowed_failure_permille": 1, "extra": 1}).to_string(),
        json!({"conditions": [{"column": "a", "min": null}], "allowed_failure_permille": 1})
            .to_string(),
        json!({"conditions": [{"column": "a", "extra": 1}], "allowed_failure_permille": 1})
            .to_string(),
        json!({"conditions": [{"min": "1"}], "allowed_failure_permille": 1}).to_string(),
        json!({"conditions": [{"column": "a", "min": 1}], "allowed_failure_permille": 1})
            .to_string(),
        json!({"conditions": [one.clone()], "allowed_failure_permille": -1}).to_string(),
        json!({"conditions": [one.clone()], "allowed_failure_permille": 1.5}).to_string(),
    ] {
        assert_eq!(parse_check(&bad), Err(CheckError::Shape), "{bad}");
    }
    assert_eq!(
        parse_check(&json!({"conditions": [], "allowed_failure_permille": 1}).to_string()),
        Err(CheckError::Conditions)
    );
    let six = json!({"conditions": vec![one; 6], "allowed_failure_permille": 1});
    assert_eq!(parse_check(&six.to_string()), Err(CheckError::Conditions));
}
