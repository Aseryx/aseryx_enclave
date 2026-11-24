//! The manifest parser accepts a real version 3 manifest and refuses everything that is not exactly that.

use aseryx_enclave_harness::manifest::{Manifest, ManifestError};
use serde_json::{Value, json};

const REAL: &str = include_str!("fixtures/real-manifest.json");

fn real() -> Value {
    serde_json::from_str(REAL).expect("fixture")
}

fn parse(value: &Value) -> Result<Manifest, ManifestError> {
    Manifest::parse(&value.to_string())
}

/// A manifest the web application wrote and pinned reads as it was written.
#[test]
fn a_real_manifest_parses() {
    let manifest = Manifest::parse(REAL).expect("manifest");
    assert_eq!(
        (
            manifest.total_size,
            manifest.chunk_size,
            manifest.file_type.as_str()
        ),
        (9519, 134_217_728, "csv")
    );
    assert_eq!(manifest.upload_name, "e2e-cutover");
    assert_eq!(
        (manifest.token_id.as_str(), manifest.dataset.as_str()),
        ("1", "5daacae0e7a77a85253e78990e040197")
    );
    assert_eq!(
        hex::encode(manifest.plaintext_sha256),
        "3fb879700d5528f2e21d654ba4cc6d149648186704ff6b07c0f6673fbc41b49f"
    );
    assert_eq!(manifest.chunks.len(), 1);
    assert_eq!(
        manifest.chunks[0].cid,
        "QmXz61oCEc9zcBRPhsDWpU4z2gtaqYXk1g5Acx1Mpyu2fC"
    );
    assert_eq!(manifest.key_wrap["format"], "aseryx-sealed-aes-key-v2");
}

/// A field with another value than the format allows is refused, and the error names the field.
#[test]
fn invalid_field_values_are_refused() {
    let cases: [(&str, Value, &str); 10] = [
        ("version", json!("aseryx-hybrid-chipotle-v2"), "version"),
        ("fileType", json!("parquet"), "fileType"),
        ("chunkSize", json!(0), "chunkSize"),
        ("chunkSize", json!(2_147_483_648u64), "chunkSize"),
        ("totalSize", json!(134_217_729u64), "totalSize"),
        ("plaintextSha256", json!("3F".repeat(32)), "plaintextSha256"),
        ("plaintextSha256", json!("3f".repeat(31)), "plaintextSha256"),
        ("plaintextSha256", json!("zz".repeat(32)), "plaintextSha256"),
        ("chunks", json!([]), "chunks"),
        (
            "chunks",
            json!(vec![
                json!({"cid": "ipfs://Qm", "iv": "AAAAAAAAAAAAAAAA"});
                4097
            ]),
            "chunks",
        ),
    ];
    for (field, value, named) in cases {
        let mut manifest = real();
        manifest[field] = value;
        assert_eq!(
            parse(&manifest),
            Err(ManifestError::Field(named_static(named))),
            "{field}"
        );
    }
}

fn named_static(name: &str) -> &'static str {
    match name {
        "version" => "version",
        "fileType" => "fileType",
        "chunkSize" => "chunkSize",
        "totalSize" => "totalSize",
        "plaintextSha256" => "plaintextSha256",
        _ => "chunks",
    }
}

/// A chunk needs an ipfs:// identifier of letters and digits and a 12-byte IV.
#[test]
fn invalid_chunks_are_refused() {
    for chunk in [
        json!({"cid": "QmNoScheme", "iv": "AAAAAAAAAAAAAAAA"}),
        json!({"cid": "ipfs://", "iv": "AAAAAAAAAAAAAAAA"}),
        json!({"cid": "ipfs://Qm/../x", "iv": "AAAAAAAAAAAAAAAA"}),
        json!({"cid": "ipfs://Qm x", "iv": "AAAAAAAAAAAAAAAA"}),
        json!({"cid": format!("ipfs://{}", "Q".repeat(129)), "iv": "AAAAAAAAAAAAAAAA"}),
        json!({"cid": "ipfs://QmFine", "iv": "AAAA"}),
        json!({"cid": "ipfs://QmFine", "iv": "not base64!"}),
        json!({"cid": "ipfs://QmFine", "iv": "AAAAAAAAAAAAAAAAAAAAAAAA"}),
    ] {
        let mut manifest = real();
        manifest["chunks"] = json!([chunk]);
        assert!(
            matches!(parse(&manifest), Err(ManifestError::Field(field)) if field.starts_with("chunks.")),
            "{chunk}"
        );
    }
}

/// The manifest has exactly its fields: none missing, none extra, and no extra field in a chunk.
#[test]
fn a_manifest_has_exactly_its_fields() {
    let manifest = real();
    for field in manifest.as_object().expect("object").keys() {
        let mut missing = manifest.clone();
        missing.as_object_mut().expect("object").remove(field);
        assert!(
            matches!(parse(&missing), Err(ManifestError::Shape(_))),
            "{field}"
        );
    }
    let mut extra = manifest.clone();
    extra["extra"] = json!(1);
    assert!(matches!(parse(&extra), Err(ManifestError::Shape(_))));
    let mut chunk_extra = manifest.clone();
    chunk_extra["chunks"][0]["extra"] = json!(1);
    assert!(matches!(parse(&chunk_extra), Err(ManifestError::Shape(_))));
    assert!(matches!(
        Manifest::parse("not json"),
        Err(ManifestError::Shape(_))
    ));
}

/// An empty file is one chunk, and the count follows the size.
#[test]
fn the_chunk_count_follows_the_size() {
    let mut manifest = real();
    manifest["totalSize"] = json!(0);
    assert!(parse(&manifest).is_ok());
    manifest["totalSize"] = json!(134_217_728u64);
    assert!(parse(&manifest).is_ok());
    manifest["totalSize"] = json!(134_217_729u64);
    assert!(parse(&manifest).is_err());
}
