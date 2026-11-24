//! The result signature is the one ethers makes, and keys are fresh per job.

use aseryx_enclave_harness::consent::Bytes32;
use aseryx_enclave_harness::keys::{KeyError, ResponseKey, ResultKey, verify_result_signature};
use serde_json::Value;

const VECTOR: &str = include_str!("fixtures/result-signature-vector.json");

fn vector() -> (ResultKey, String, Bytes32, [u8; 65]) {
    let v: Value = serde_json::from_str(VECTOR).expect("vector");
    let text = |name: &str| v[name].as_str().expect(name).to_owned();
    let secret: [u8; 32] = hex::decode(&text("secret")[2..])
        .expect("secret")
        .try_into()
        .expect("32 bytes");
    let signature: [u8; 65] = hex::decode(&text("signature")[2..])
        .expect("signature")
        .try_into()
        .expect("65 bytes");
    (
        ResultKey::from_secret(&secret).expect("key"),
        text("publicKey")[2..].to_owned(),
        Bytes32::parse(&text("digest")).expect("digest"),
        signature,
    )
}

/// The key, its public key and its signature over the result digest equal the ones ethers produces.
#[test]
fn the_signature_equals_the_one_ethers_makes() {
    let (key, public, digest, signature) = vector();
    assert_eq!(key.public_hex(), public);
    assert_eq!(key.sign(&digest), signature);
    assert_eq!(
        verify_result_signature(&public, &digest, &signature),
        Ok(true)
    );
}

/// A signature verifies only for its digest and its key.
#[test]
fn a_signature_verifies_only_for_its_digest_and_key() {
    let (key, public, digest, signature) = vector();
    let other_digest = Bytes32([0x42; 32]);
    assert_eq!(
        verify_result_signature(&public, &other_digest, &signature),
        Ok(false)
    );
    let other_key = ResultKey::generate().expect("key");
    assert_eq!(
        verify_result_signature(&other_key.public_hex(), &digest, &key.sign(&digest)),
        Ok(false)
    );
}

/// Malformed signatures and public keys are refused with a typed error.
#[test]
fn malformed_signatures_and_keys_are_refused() {
    let (_, public, digest, signature) = vector();
    for v in [0u8, 26, 29, 255] {
        let mut bad = signature;
        bad[64] = v;
        assert_eq!(
            verify_result_signature(&public, &digest, &bad),
            Err(KeyError::Signature),
            "v={v}"
        );
    }
    let mut zero_r = signature;
    zero_r[..32].fill(0);
    assert_eq!(
        verify_result_signature(&public, &digest, &zero_r),
        Err(KeyError::Signature)
    );
    for bad in [
        "",
        "zz",
        &public[..64],
        &format!("04{}", &public[2..]),
        &format!("{public}00"),
    ] {
        assert_eq!(
            verify_result_signature(bad, &digest, &signature),
            Err(KeyError::PublicKey),
            "{bad}"
        );
    }
}

/// Every signature has a low s, the form ethers accepts, and recovers the signing key.
#[test]
fn every_signature_has_a_low_s_and_recovers() {
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    let key = ResultKey::generate().expect("key");
    let public = key.public_hex();
    for n in 0..64u8 {
        let digest = Bytes32([n; 32]);
        let signature = key.sign(&digest);
        assert!(signature[32..64] <= HALF_ORDER[..], "s is high for {n}");
        assert!(matches!(signature[64], 27 | 28));
        assert_eq!(
            verify_result_signature(&public, &digest, &signature),
            Ok(true),
            "{n}"
        );
    }
}

/// Keys are fresh and have the shapes runtime data carries.
#[test]
fn keys_are_fresh_and_have_the_expected_shapes() {
    let (a, b) = (
        ResultKey::generate().expect("key"),
        ResultKey::generate().expect("key"),
    );
    assert_ne!(a.public_hex(), b.public_hex());
    assert_eq!(a.public_hex().len(), 66);
    assert!(a.public_hex().starts_with("02") || a.public_hex().starts_with("03"));
    let (c, d) = (
        ResponseKey::generate().expect("key"),
        ResponseKey::generate().expect("key"),
    );
    assert_ne!(c.public_hex(), d.public_hex());
    assert_eq!(c.public_hex().len(), 64);
    assert!(
        c.public_hex()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
}
