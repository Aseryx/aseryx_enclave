//! Proofs over the production circuits: the witness equals `ark-circom`'s, every proof verifies against the circuit's
//! `verification_key.json` read independently of the proving key, and the pins hold. The circuit artifacts come from
//! `ENCLAVE_CIRCUITS` (`make test` sets it and fetches the circuits).

mod common;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof as ArkProof, VerifyingKey};
use ark_snark::SNARK;
use aseryx_enclave_harness::circom::Circuit;
use aseryx_enclave_harness::engine::NativeEngine;
use aseryx_enclave_harness::job::Prover;
use aseryx_enclave_harness::prove::{
    ArkProver, ArtifactFile, ArtifactSource, ProveFailure, parse_pins,
};
use num_bigint::{BigInt, BigUint};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

const PINS: &str = include_str!("../circuit-pins.json");
const APPRAISAL: &str = "tabular_appraisal_r7";
const THRESHOLD: &str = "threshold_r2_c1";

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} is not set; run the tests with `make test`")),
    )
}

struct Dir(PathBuf);
impl ArtifactSource for Dir {
    fn artifact(&self, circuit: &str, file: ArtifactFile) -> Result<Vec<u8>, ProveFailure> {
        std::fs::read(self.0.join(circuit).join(file.name())).map_err(|_| ProveFailure::Fetch)
    }
}

fn source() -> Dir {
    Dir(env_path("ENCLAVE_CIRCUITS"))
}

fn engine() -> NativeEngine {
    common::native_engine()
}

fn golden() -> Vec<u8> {
    std::fs::read(env_path("ENCLAVE_TABULAR_FIXTURES").join("goldens/comma-clean.csv"))
        .expect("golden")
}

fn feed(mut run: aseryx_enclave_harness::engine::Run, plain: &[u8]) -> String {
    loop {
        run.feed(plain).expect("feed");
        if !run.next_pass().expect("pass") {
            return run.finish().expect("finish");
        }
    }
}

/// The engine's appraisal of a golden, and the circuit input of a threshold count over it with the given conditions.
fn world(conditions: Value) -> (Value, String) {
    let module = engine();
    let plain = golden();
    let appraisal: Value = serde_json::from_str(&feed(
        module
            .appraisal(
                "comma-clean.csv",
                "csv",
                Some(&"ab".repeat(32)),
                Some("QmManifest"),
            )
            .expect("start"),
        &plain,
    ))
    .expect("json");
    let label = serde_json::to_string(&appraisal["label"]).expect("label");
    let check = json!({"conditions": conditions, "allowed_failure_permille": 100}).to_string();
    let counted = feed(
        module.threshold_count(&label, &check).expect("start"),
        &plain,
    );
    let witness = module
        .threshold_witness(&counted, "12345", 100)
        .expect("witness");
    (appraisal, witness)
}

fn one_condition() -> Value {
    json!([{"column": "amount", "min": "10", "max": "60"}])
}

fn witnesses() -> (Value, String) {
    world(one_condition())
}

fn integer(v: &Value) -> BigUint {
    v.as_str()
        .map_or_else(|| v.to_string(), str::to_owned)
        .parse()
        .expect("integer")
}

/// The circuit inputs of a witness: a scalar is a one-element list.
fn inputs(json_text: &str) -> BTreeMap<String, Vec<BigUint>> {
    let value: Value = serde_json::from_str(json_text).expect("json");
    value
        .as_object()
        .expect("object")
        .iter()
        .map(|(k, v)| {
            let values = v.as_array().map_or_else(
                || vec![integer(v)],
                |items| items.iter().map(integer).collect(),
            );
            (k.clone(), values)
        })
        .collect()
}

fn wasm_of(name: &str) -> Vec<u8> {
    std::fs::read(env_path("ENCLAVE_CIRCUITS").join(name).join("circuit.wasm")).expect("wasm")
}

fn reference_witness(name: &str, witness: &BTreeMap<String, Vec<BigUint>>) -> Vec<Fr> {
    let mut store = wasmer::Store::default();
    let path = env_path("ENCLAVE_CIRCUITS").join(name).join("circuit.wasm");
    let mut calc = ark_circom::WitnessCalculator::new(&mut store, path).expect("ark-circom");
    let map: HashMap<String, Vec<BigInt>> = witness
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().cloned().map(BigInt::from).collect()))
        .collect();
    calc.calculate_witness_element::<Fr, _>(&mut store, map, false)
        .expect("reference witness")
}

/// The witness computed under wasmtime equals the one `ark-circom` computes with wasmer, for both circuit families.
#[test]
fn the_witness_equals_ark_circoms() {
    let (appraisal, threshold) = witnesses();
    for (name, text) in [
        (APPRAISAL, appraisal["witness"].to_string()),
        (THRESHOLD, threshold),
    ] {
        let given = inputs(&text);
        let ours = Circuit::new(&wasm_of(name))
            .expect("circuit")
            .witness(&given)
            .expect("witness");
        assert_eq!(ours, reference_witness(name, &given), "{name}");
        assert!(ours.len() > 100);
    }
}

fn fq(text: &Value) -> Fq {
    Fq::from(
        text.as_str()
            .expect("string")
            .parse::<BigUint>()
            .expect("decimal"),
    )
}

fn fq2(pair: &Value) -> Fq2 {
    Fq2::new(fq(&pair[0]), fq(&pair[1]))
}

fn g1(point: &Value) -> G1Affine {
    G1Affine::new(fq(&point[0]), fq(&point[1]))
}

fn g2(point: &Value) -> G2Affine {
    G2Affine::new(fq2(&point[0]), fq2(&point[1]))
}

/// A verification key read from the `verification_key.json` file, with no use of the proving key.
fn verification_key(name: &str) -> VerifyingKey<Bn254> {
    let v: Value = serde_json::from_slice(
        &std::fs::read(
            env_path("ENCLAVE_CIRCUITS")
                .join(name)
                .join("verification_key.json"),
        )
        .expect("vk"),
    )
    .expect("json");
    VerifyingKey {
        alpha_g1: g1(&v["vk_alpha_1"]),
        beta_g2: g2(&v["vk_beta_2"]),
        gamma_g2: g2(&v["vk_gamma_2"]),
        delta_g2: g2(&v["vk_delta_2"]),
        gamma_abc_g1: v["IC"].as_array().expect("IC").iter().map(g1).collect(),
    }
}

fn verifies(name: &str, proof_text: &str, public: &[String]) -> bool {
    let p: Value = serde_json::from_str(proof_text).expect("proof");
    let proof = ArkProof::<Bn254> {
        a: g1(&p["pi_a"]),
        b: g2(&p["pi_b"]),
        c: g1(&p["pi_c"]),
    };
    let inputs: Vec<Fr> = public
        .iter()
        .map(|s| Fr::from(s.parse::<BigUint>().expect("decimal")))
        .collect();
    let prepared = Groth16::<Bn254>::process_vk(&verification_key(name)).expect("vk");
    Groth16::<Bn254>::verify_with_processed_vk(&prepared, &inputs, &proof).expect("verify")
}

fn prover(source: &Dir) -> ArkProver<'_> {
    ArkProver::new(parse_pins(PINS).expect("pins"), source)
}

/// An appraisal proof verifies against the circuit's verification key file and carries the engine's own public values.
#[test]
fn an_appraisal_proof_verifies_and_carries_the_engines_values() {
    let (appraisal, _) = witnesses();
    let src = source();
    let proof = prover(&src)
        .try_prove(APPRAISAL, &appraisal["witness"].to_string())
        .expect("proof");
    assert_eq!(proof.public_signals.len(), 12);
    assert!(verifies(APPRAISAL, &proof.text, &proof.public_signals));
    assert_eq!(
        proof.public_signals[0],
        appraisal["quality"]["score"].to_string()
    );
    assert_eq!(
        proof.public_signals[7],
        appraisal["hashes"]["plaintext_hash"]
            .as_str()
            .expect("hash")
    );
    assert_eq!(
        proof.public_signals[8],
        appraisal["hashes"]["label_hash"].as_str().expect("hash")
    );
    assert_eq!(
        proof.public_signals[11],
        appraisal["inputsCommitment"].as_str().expect("commitment")
    );
    let shape: Value = serde_json::from_str(&proof.text).expect("json");
    assert_eq!(
        (shape["protocol"].as_str(), shape["curve"].as_str()),
        (Some("groth16"), Some("bn128"))
    );
    assert_eq!(
        (
            shape["pi_a"].as_array().map(Vec::len),
            shape["pi_b"].as_array().map(Vec::len),
            shape["pi_c"].as_array().map(Vec::len)
        ),
        (Some(3), Some(3), Some(3))
    );
    let mut other = proof.public_signals.clone();
    other[0] = "42".to_owned();
    assert!(
        !verifies(APPRAISAL, &proof.text, &other),
        "a proof must not verify for other public signals"
    );
}

/// A threshold proof verifies and carries the check hash and the engine's band and answer.
#[test]
fn a_threshold_proof_verifies_and_carries_the_check_hash() {
    let (_, witness) = witnesses();
    let src = source();
    let proof = prover(&src).try_prove(THRESHOLD, &witness).expect("proof");
    assert_eq!(proof.public_signals.len(), 7);
    assert!(verifies(THRESHOLD, &proof.text, &proof.public_signals));
    assert_eq!(proof.public_signals[3], "12345");
    assert_eq!(proof.public_signals[6], "100");
}

/// Two proofs of one witness differ (fresh randomness) and both verify.
#[test]
fn proofs_are_randomised() {
    let (appraisal, _) = witnesses();
    let src = source();
    let prover = prover(&src);
    let (a, b) = (
        prover
            .try_prove(APPRAISAL, &appraisal["witness"].to_string())
            .expect("a"),
        prover
            .try_prove(APPRAISAL, &appraisal["witness"].to_string())
            .expect("b"),
    );
    assert_ne!(a.text, b.text);
    assert_eq!(a.public_signals, b.public_signals);
    assert!(verifies(APPRAISAL, &b.text, &b.public_signals));
}

/// A circuit that is not pinned, a file that is not the pinned one and an artifact that cannot be fetched are refused.
#[test]
fn unpinned_circuits_and_files_that_differ_from_their_pin_are_refused() {
    let (appraisal, _) = witnesses();
    let src = source();
    let witness = appraisal["witness"].to_string();
    assert_eq!(
        prover(&src).try_prove("tabular_appraisal_r8", &witness),
        Err(ProveFailure::Unpinned("tabular_appraisal_r8".to_owned()))
    );
    for field in ["wasm", "zkey", "verificationKey"] {
        let mut pins = parse_pins(PINS).expect("pins");
        let pin = pins.get_mut(APPRAISAL).expect("pin");
        let target: &mut [u8; 32] = match field {
            "wasm" => &mut pin.wasm,
            "zkey" => &mut pin.zkey,
            _ => &mut pin.verification_key,
        };
        target[0] ^= 1;
        assert_eq!(
            ArkProver::new(pins, &src).try_prove(APPRAISAL, &witness),
            Err(ProveFailure::NotPinned),
            "{field}"
        );
    }
    let empty = Dir(std::env::temp_dir().join("enclave-no-circuits"));
    assert_eq!(
        ArkProver::new(parse_pins(PINS).expect("pins"), &empty).try_prove(APPRAISAL, &witness),
        Err(ProveFailure::Fetch)
    );
}

/// Witnesses that are not objects of non-negative integers, or that do not fit the field, are refused.
#[test]
fn witnesses_that_are_not_circuit_inputs_are_refused() {
    let src = source();
    let prover = prover(&src);
    let too_big = format!("{{\"rows\": \"{}\"}}", "9".repeat(80));
    for bad in [
        "not json",
        "[]",
        "{}",
        "{\"rows\": []}",
        "{\"rows\": [[1]]}",
        "{\"rows\": -1}",
        "{\"rows\": 1.5}",
        "{\"rows\": \"x\"}",
        "{\"rows\": null}",
        "{\"rows\": \"\"}",
        too_big.as_str(),
    ] {
        assert!(
            matches!(
                prover.try_prove(APPRAISAL, bad),
                Err(ProveFailure::Witness(_))
            ),
            "{bad}"
        );
    }
}

/// The prover trait maps every failure to the one error the job reports as prove_failed.
#[test]
fn the_prover_trait_reports_one_error() {
    let src = source();
    assert!(prover(&src).prove("nothing", "{}").is_err());
}

/// The pins file must be exactly circuit names with three hashes each.
#[test]
fn malformed_pins_are_refused() {
    let hash = "00".repeat(32);
    let good = format!(
        "{{\"a\": {{\"wasm\": \"{hash}\", \"zkey\": \"{hash}\", \"verificationKey\": \"{hash}\"}}}}"
    );
    assert!(parse_pins(&good).is_ok());
    let short = format!(
        "{{\"a\": {{\"wasm\": \"{}\", \"zkey\": \"{hash}\", \"verificationKey\": \"{hash}\"}}}}",
        "00".repeat(31)
    );
    let extra = format!(
        "{{\"a\": {{\"wasm\": \"{hash}\", \"zkey\": \"{hash}\", \"verificationKey\": \"{hash}\", \"x\": \"{hash}\"}}}}"
    );
    let missing = format!("{{\"a\": {{\"wasm\": \"{hash}\", \"zkey\": \"{hash}\"}}}}");
    for bad in [
        "",
        "[]",
        "{\"a\": 1}",
        short.as_str(),
        extra.as_str(),
        missing.as_str(),
    ] {
        assert_eq!(parse_pins(bad), Err(ProveFailure::Pins), "{bad}");
    }
    assert_eq!(parse_pins(PINS).expect("the committed pins").len(), 6);
}

/// Prime check: the circuits work over the field arkworks proves in.
#[test]
fn the_field_is_bn254() {
    assert_eq!(
        Fr::MODULUS.to_string(),
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    );
}

/// A source that serves the pinned artifacts with one verification key replaced.
struct PatchedKey(Dir, Vec<u8>);

impl ArtifactSource for PatchedKey {
    fn artifact(&self, circuit: &str, file: ArtifactFile) -> Result<Vec<u8>, ProveFailure> {
        match file {
            ArtifactFile::VerificationKey => Ok(self.1.clone()),
            _ => self.0.artifact(circuit, file),
        }
    }
}

/// A verification key that names another number of public signals than the proving key has is refused, even when its
/// hash is the pinned one.
#[test]
fn a_verification_key_that_disagrees_with_the_proving_key_is_refused() {
    let (appraisal, _) = witnesses();
    let mut key: Value = serde_json::from_slice(
        &source()
            .artifact(APPRAISAL, ArtifactFile::VerificationKey)
            .expect("vk"),
    )
    .expect("json");
    key["nPublic"] = json!(11);
    let patched = serde_json::to_vec(&key).expect("vk");
    let mut pins = parse_pins(PINS).expect("pins");
    pins.get_mut(APPRAISAL).expect("pin").verification_key = Sha256::digest(&patched).into();
    let src = PatchedKey(source(), patched);
    assert!(matches!(
        ArkProver::new(pins, &src).try_prove(APPRAISAL, &appraisal["witness"].to_string()),
        Err(ProveFailure::Artifacts(_))
    ));
}

/// A threshold proof over two conditions has array inputs with positions above the first, and verifies.
#[test]
fn a_two_condition_threshold_proof_verifies() {
    let conditions = json!([
        {"column": "amount", "min": "10", "max": "60"},
        {"column": "count", "min": "0", "max": "1000"}
    ]);
    let (_, witness) = world(conditions);
    let given = inputs(&witness);
    assert!(given.values().any(|v| v.len() == 2), "{witness}");
    let name = "threshold_r2_c2";
    let ours = Circuit::new(&wasm_of(name))
        .expect("circuit")
        .witness(&given)
        .expect("witness");
    assert_eq!(ours, reference_witness(name, &given));
    let src = source();
    let proof = prover(&src).try_prove(name, &witness).expect("proof");
    assert!(verifies(name, &proof.text, &proof.public_signals));
}

/// Inputs that are not the circuit's, whether one is missing, unknown or the wrong length, are refused.
#[test]
fn inputs_that_do_not_match_the_circuit_are_refused() {
    let (_, witness) = witnesses();
    let src = source();
    let prover = prover(&src);
    let whole: serde_json::Map<String, Value> = serde_json::from_str(&witness).expect("json");
    assert!(prover.try_prove(THRESHOLD, &witness).is_ok());
    let array = whole
        .iter()
        .find(|(_, v)| v.is_array())
        .map(|(k, _)| k.clone())
        .expect("an array input");
    let scalar = whole
        .iter()
        .find(|(_, v)| !v.is_array())
        .map(|(k, _)| k.clone())
        .expect("a scalar input");
    let mut cases = Vec::new();
    for (label, edit) in [
        ("missing scalar", 0),
        ("missing array", 1),
        ("unknown", 2),
        ("longer array", 3),
        ("shorter array", 4),
        ("one missing and one unknown", 5),
    ] {
        let mut m = whole.clone();
        match edit {
            0 => drop(m.remove(&scalar)),
            1 => drop(m.remove(&array)),
            2 => drop(m.insert("nosuchsignal".to_owned(), json!("1"))),
            3 => m
                .get_mut(&array)
                .and_then(Value::as_array_mut)
                .expect("array")
                .push(json!("1")),
            5 => {
                m.remove(&scalar);
                m.insert("nosuchsignal".to_owned(), json!("1"));
            }
            _ => drop(
                m.get_mut(&array)
                    .and_then(Value::as_array_mut)
                    .expect("array")
                    .pop(),
            ),
        }
        cases.push((label, Value::Object(m).to_string()));
    }
    for (label, text) in cases {
        assert!(
            matches!(
                prover.try_prove(THRESHOLD, &text),
                Err(ProveFailure::Witness(_))
            ),
            "{label}"
        );
    }
}

/// The verification key hash of each production circuit row (`public.circuit.verification_key_hash`, read 2026-11-24).
/// The API hashes the raw bytes of `verification_key.json` with SHA-256, as the pins do.
const PRODUCTION_ROWS: [(&str, &str); 6] = [
    (
        "tabular_appraisal_r7",
        "986426016d94b3e7a28f274b0c8ffa5e432bee4bd5637b6b51ffbf705418085d",
    ),
    (
        "threshold_r2_c1",
        "d7bf82da36abb2f66f956e84d115f29f8cf51e45bc29ea845881a86cf4cc41b5",
    ),
    (
        "threshold_r2_c2",
        "5701c3dd3f8c873b46a058d7b98e53ae8e751e80aa39cdb3b3e6e81694e2a0b6",
    ),
    (
        "threshold_r2_c3",
        "f5b733b4296ebebdd815fd0e4f87c322d679638eda4f506e4d16ca9860d50504",
    ),
    (
        "threshold_r2_c4",
        "d69e01024155922b8017b75159da8b15843238eb3b3ac6cc4454dc725e3f74d5",
    ),
    (
        "threshold_r2_c5",
        "63ec38384d36768e9f8f1f1a5117f66f3064ad6a53e376165410af96c23ae3e6",
    ),
];

/// The pinned verification keys, and the files fetched for them, hash to what the API's circuit rows record.
#[test]
fn the_pinned_verification_keys_are_the_production_circuits() {
    let pins = parse_pins(PINS).expect("pins");
    assert_eq!(pins.len(), PRODUCTION_ROWS.len());
    for (name, row) in PRODUCTION_ROWS {
        let fetched = source()
            .artifact(name, ArtifactFile::VerificationKey)
            .expect("verification key");
        assert_eq!(hex::encode(Sha256::digest(&fetched)), row, "{name} file");
        assert_eq!(hex::encode(pins[name].verification_key), row, "{name} pin");
    }
}
