//! Groth16 proofs of the engine's witnesses, over circuit artifacts pinned by hash.
//!
//! A circuit is a public `circuit.wasm` (the witness calculator), a public `proving_key.zkey` and a public
//! `verification_key.json`. A release pins the SHA-256 of all three per circuit name; the workload fetches them, refuses
//! any that differ from the pin, computes the witness under wasmtime, proves with arkworks and checks its own proof
//! against the key before returning it. A circuit that is rebuilt has new keys, so it needs a new pins file, a new image
//! and new consents.

use crate::circom::Circuit;
use crate::job::{ProveError, Prover};
use crate::qap::SnarkjsReduction;
use crate::result::Proof;
use crate::zkey::{Zkey, read_zkey};
use ark_bn254::{Bn254, Fq, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const FETCH_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_ARTIFACT_BYTES: u64 = 256 << 20;

/// Why a proof could not be made.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProveFailure {
    /// The pins file is not a map of circuit names to three SHA-256 hashes.
    #[error("the circuit pins are malformed")]
    Pins,
    /// No pin names this circuit.
    #[error("no pinned circuit {0}")]
    Unpinned(String),
    /// An artifact could not be fetched.
    #[error("a circuit artifact could not be fetched")]
    Fetch,
    /// An artifact is not the pinned one.
    #[error("a circuit artifact is not the pinned one")]
    NotPinned,
    /// An artifact does not parse, or the circuit does not match its key.
    #[error("the circuit artifacts are not usable: {0}")]
    Artifacts(String),
    /// The witness is not an object of numbers, or the circuit rejects it.
    #[error("the witness is not usable: {0}")]
    Witness(String),
    /// The proof could not be made or did not verify against its own key.
    #[error("the proof could not be made")]
    Proof,
}

/// The three files of a circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactFile {
    /// `circuit.wasm`, the witness calculator.
    Wasm,
    /// `proving_key.zkey`.
    Zkey,
    /// `verification_key.json`.
    VerificationKey,
}

impl ArtifactFile {
    /// The file's name in the artifact store.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Wasm => "circuit.wasm",
            Self::Zkey => "proving_key.zkey",
            Self::VerificationKey => "verification_key.json",
        }
    }
}

/// The SHA-256 of each file of a pinned circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitPin {
    /// The hash of `circuit.wasm`.
    pub wasm: [u8; 32],
    /// The hash of `proving_key.zkey`.
    pub zkey: [u8; 32],
    /// The hash of `verification_key.json`.
    pub verification_key: [u8; 32],
}

/// Parses the pins file: `{"<circuit>": {"wasm": "<64 hex>", "zkey": "<64 hex>", "verificationKey": "<64 hex>"}}`.
///
/// # Errors
///
/// [`ProveFailure::Pins`] for anything else.
pub fn parse_pins(text: &str) -> Result<BTreeMap<String, CircuitPin>, ProveFailure> {
    let value: BTreeMap<String, BTreeMap<String, String>> =
        serde_json::from_str(text).map_err(|_| ProveFailure::Pins)?;
    let hash = |fields: &BTreeMap<String, String>, name: &str| -> Result<[u8; 32], ProveFailure> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(fields.get(name).ok_or(ProveFailure::Pins)?, &mut out)
            .map_err(|_| ProveFailure::Pins)?;
        Ok(out)
    };
    value
        .into_iter()
        .map(|(name, fields)| {
            if fields.len() != 3 {
                return Err(ProveFailure::Pins);
            }
            let pin = CircuitPin {
                wasm: hash(&fields, "wasm")?,
                zkey: hash(&fields, "zkey")?,
                verification_key: hash(&fields, "verificationKey")?,
            };
            Ok((name, pin))
        })
        .collect()
}

/// Where circuit artifacts come from.
pub trait ArtifactSource: Sync {
    /// The bytes of one file of a circuit.
    ///
    /// # Errors
    ///
    /// [`ProveFailure::Fetch`] if they cannot be had.
    fn artifact(&self, circuit: &str, file: ArtifactFile) -> Result<Vec<u8>, ProveFailure>;
}

/// The public artifact bucket: `<base>/<appraisal|threshold>/<circuit>/<file>`.
pub struct BucketSource {
    base: String,
    agent: ureq::Agent,
}

impl BucketSource {
    /// A source at `base`, for example `https://<project>.supabase.co/storage/v1/object/public/zk-artifacts`.
    #[must_use]
    pub fn new(base: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(FETCH_TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            base: base.trim_end_matches('/').to_owned(),
            agent,
        }
    }
}

impl ArtifactSource for BucketSource {
    fn artifact(&self, circuit: &str, file: ArtifactFile) -> Result<Vec<u8>, ProveFailure> {
        let folder = if circuit.starts_with("threshold_") {
            "threshold"
        } else {
            "appraisal"
        };
        if !circuit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(ProveFailure::Fetch);
        }
        let mut response = self
            .agent
            .get(format!("{}/{folder}/{circuit}/{}", self.base, file.name()))
            .call()
            .map_err(|_| ProveFailure::Fetch)?;
        if response.status().as_u16() != 200 {
            return Err(ProveFailure::Fetch);
        }
        response
            .body_mut()
            .with_config()
            .limit(MAX_ARTIFACT_BYTES)
            .read_to_vec()
            .map_err(|_| ProveFailure::Fetch)
    }
}

struct Loaded {
    circuit: Circuit,
    zkey: Zkey,
}

/// A prover over pinned circuits. Each circuit is fetched, checked and parsed once, on first use.
pub struct ArkProver<'a> {
    pins: BTreeMap<String, CircuitPin>,
    source: &'a dyn ArtifactSource,
    loaded: Mutex<HashMap<String, Arc<Loaded>>>,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn decimal(value: &Fq) -> String {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_string()
}

fn decimal_fr(value: &Fr) -> String {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_string()
}

impl<'a> ArkProver<'a> {
    /// A prover for the pinned circuits, fetching artifacts from `source`.
    #[must_use]
    pub fn new(pins: BTreeMap<String, CircuitPin>, source: &'a dyn ArtifactSource) -> Self {
        Self {
            pins,
            source,
            loaded: Mutex::new(HashMap::new()),
        }
    }

    fn load(&self, name: &str) -> Result<Arc<Loaded>, ProveFailure> {
        let pin = self
            .pins
            .get(name)
            .ok_or_else(|| ProveFailure::Unpinned(name.chars().take(64).collect()))?;
        if let Some(loaded) = self
            .loaded
            .lock()
            .map_err(|_| ProveFailure::Proof)?
            .get(name)
        {
            return Ok(Arc::clone(loaded));
        }
        let wasm = self.source.artifact(name, ArtifactFile::Wasm)?;
        let zkey_bytes = self.source.artifact(name, ArtifactFile::Zkey)?;
        let vk = self.source.artifact(name, ArtifactFile::VerificationKey)?;
        if sha256(&wasm) != pin.wasm
            || sha256(&zkey_bytes) != pin.zkey
            || sha256(&vk) != pin.verification_key
        {
            return Err(ProveFailure::NotPinned);
        }
        let circuit = Circuit::new(&wasm).map_err(|e| ProveFailure::Artifacts(e.to_string()))?;
        let zkey = read_zkey(&zkey_bytes).map_err(|e| ProveFailure::Artifacts(e.to_string()))?;
        let vk: Value = serde_json::from_slice(&vk)
            .map_err(|_| ProveFailure::Artifacts("verification key".to_owned()))?;
        if vk["nPublic"].as_u64().map(|n| n + 1)
            != u64::try_from(zkey.matrices.num_instance_variables).ok()
        {
            return Err(ProveFailure::Artifacts(
                "the verification key and the proving key disagree".to_owned(),
            ));
        }
        let loaded = Arc::new(Loaded { circuit, zkey });
        self.loaded
            .lock()
            .map_err(|_| ProveFailure::Proof)?
            .insert(name.to_owned(), Arc::clone(&loaded));
        Ok(loaded)
    }

    /// The proof of `witness_json`, an object of decimal strings and integers, for the pinned circuit `name`.
    ///
    /// # Errors
    ///
    /// [`ProveFailure`]: an unpinned circuit, artifacts that cannot be fetched or are not the pinned ones, a witness the
    /// circuit rejects, or a proof that does not verify against its own key.
    pub fn try_prove(&self, name: &str, witness_json: &str) -> Result<Proof, ProveFailure> {
        let loaded = self.load(name)?;
        let inputs = parse_inputs(witness_json)?;
        let full = loaded
            .circuit
            .witness(&inputs)
            .map_err(|e| ProveFailure::Witness(e.to_string()))?;
        let m = &loaded.zkey.matrices;
        let public = full.get(1..m.num_instance_variables).ok_or_else(|| {
            ProveFailure::Witness("the witness is shorter than the public inputs".to_owned())
        })?;
        let (r, s) = (random_scalar()?, random_scalar()?);
        let matrices = [m.a.clone(), m.b.clone(), Vec::new()];
        let proof = Groth16::<Bn254, SnarkjsReduction>::create_proof_with_reduction_and_matrices(
            &loaded.zkey.proving_key,
            r,
            s,
            &matrices,
            m.num_instance_variables,
            m.num_constraints,
            &full,
        )
        .map_err(|_| ProveFailure::Proof)?;
        let prepared = Groth16::<Bn254>::process_vk(&loaded.zkey.proving_key.vk)
            .map_err(|_| ProveFailure::Proof)?;
        if !Groth16::<Bn254>::verify_with_processed_vk(&prepared, public, &proof)
            .map_err(|_| ProveFailure::Proof)?
        {
            return Err(ProveFailure::Proof);
        }
        let text = json!({
            "pi_a": [decimal(&proof.a.x), decimal(&proof.a.y), "1"],
            "pi_b": [[decimal(&proof.b.x.c0), decimal(&proof.b.x.c1)], [decimal(&proof.b.y.c0), decimal(&proof.b.y.c1)], ["1", "0"]],
            "pi_c": [decimal(&proof.c.x), decimal(&proof.c.y), "1"],
            "protocol": "groth16",
            "curve": "bn128",
        })
        .to_string();
        Ok(Proof {
            text,
            public_signals: public.iter().map(decimal_fr).collect(),
        })
    }
}

fn random_scalar() -> Result<Fr, ProveFailure> {
    let mut bytes = [0u8; 48];
    getrandom::fill(&mut bytes).map_err(|_| ProveFailure::Proof)?;
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

fn parse_integer(name: &str, v: &Value) -> Result<BigUint, ProveFailure> {
    let text = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_u64() => n.to_string(),
        _ => {
            return Err(ProveFailure::Witness(format!(
                "input {name} is not a non-negative integer"
            )));
        }
    };
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ProveFailure::Witness(format!(
            "input {name} is not a decimal integer"
        )));
    }
    text.parse::<BigUint>()
        .map_err(|_| ProveFailure::Witness(format!("input {name}")))
}

/// The circuit inputs of a witness object: each value is a non-negative integer or a flat array of them.
fn parse_inputs(witness_json: &str) -> Result<BTreeMap<String, Vec<BigUint>>, ProveFailure> {
    let value: Value = serde_json::from_str(witness_json)
        .map_err(|_| ProveFailure::Witness("not JSON".to_owned()))?;
    let object = value
        .as_object()
        .ok_or_else(|| ProveFailure::Witness("not an object".to_owned()))?;
    object
        .iter()
        .map(|(name, v)| {
            let values = match v {
                Value::Array(items) => items
                    .iter()
                    .map(|item| parse_integer(name, item))
                    .collect::<Result<Vec<_>, _>>()?,
                other => vec![parse_integer(name, other)?],
            };
            Ok((name.clone(), values))
        })
        .collect()
}

impl Prover for ArkProver<'_> {
    fn prove(&self, circuit: &str, witness_json: &str) -> Result<Proof, ProveError> {
        self.try_prove(circuit, witness_json)
            .map_err(|_| ProveError)
    }
}
