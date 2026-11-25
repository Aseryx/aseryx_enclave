//! The signed results a workload posts: an appraisal, a threshold answer per check, a dispute check, or an error code.
//!
//! A result is a flat object of strings, booleans and small integers (the engine's snake_case parts travel as JSON text
//! inside a string field), so it is canonical JSON and the secp256k1 result key signs its digest. The API recomputes the
//! digest and checks the signature against the key in the attested runtime data.

use crate::consent::{Bytes32, ConsentError, Uint256, result_digest};
use crate::error_code::ErrorCode;
use crate::keys::ResultKey;
use serde_json::{Map, Value, json};

const RESULT_VERSION: u64 = 1;
const COUNT_NAMES: [&str; 12] = [
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
    "conflicts_a",
];
const APPRAISAL_SIGNALS: usize = 12;
const THRESHOLD_SIGNALS: usize = 7;

/// Why a result could not be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResultError {
    /// The engine's output lacks a field the result needs, or a field has the wrong type.
    #[error("the engine output has no usable {0}")]
    Engine(&'static str),
    /// The plaintext hash the engine computed is not the one the registry holds.
    #[error("the engine hashed other bytes than the registered ones")]
    PlaintextHash,
    /// The proof has the wrong number of public signals.
    #[error("the proof has {0} public signals, not {1}")]
    Signals(usize, usize),
    /// The result is not canonical JSON.
    #[error("the result is not canonical: {0}")]
    Canonical(#[from] ConsentError),
}

/// What the workload knows about the job, the same for every result it posts.
#[derive(Debug, Clone)]
pub struct JobFacts {
    /// The job id.
    pub job_id: Bytes32,
    /// The workload identity the consent names.
    pub workload_identity: Bytes32,
    /// The appraisal family.
    pub family: String,
    /// The rules version.
    pub rules_version: String,
    /// The Digital Key token id.
    pub token_id: String,
    /// The dataset's registry id.
    pub dataset: String,
    /// The manifest's content identifier.
    pub manifest_cid: String,
    /// The full SHA-256 of the plaintext, equal to the registry's.
    pub plaintext_hash: Bytes32,
    /// The engine module's version.
    pub engine_version: String,
    /// The SHA-256 of the engine module that ran.
    pub engine_module_sha256: Bytes32,
}

/// A Groth16 proof as snarkjs writes it, with its public signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The proof's JSON text.
    pub text: String,
    /// The public signals as decimal strings, in circuit order.
    pub public_signals: Vec<String>,
}

fn base(facts: &JobFacts, kind: &str) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("v".into(), json!(RESULT_VERSION));
    object.insert("kind".into(), json!(kind));
    object.insert("jobId".into(), json!(facts.job_id.to_string()));
    object.insert(
        "workloadIdentity".into(),
        json!(facts.workload_identity.to_string()),
    );
    object.insert("family".into(), json!(facts.family));
    object.insert("rulesVersion".into(), json!(facts.rules_version));
    object.insert("tokenId".into(), json!(facts.token_id));
    object.insert("dataset".into(), json!(facts.dataset));
    object.insert("manifestCid".into(), json!(facts.manifest_cid));
    object.insert(
        "plaintextHash".into(),
        json!(facts.plaintext_hash.to_string()),
    );
    object
}

fn with_engine(mut object: Map<String, Value>, facts: &JobFacts) -> Map<String, Value> {
    object.insert("engineVersion".into(), json!(facts.engine_version));
    object.insert(
        "engineModuleSha256".into(),
        json!(hex::encode(facts.engine_module_sha256.0)),
    );
    object
}

fn text<'a>(value: &'a Value, name: &'static str) -> Result<&'a str, ResultError> {
    value.as_str().ok_or(ResultError::Engine(name))
}

/// The plaintext hash as the engine reports it: the first 31 bytes of the SHA-256, as a decimal field element.
fn field_of(hash: &Bytes32) -> String {
    let mut bytes = [0u8; 32];
    bytes[1..].copy_from_slice(&hash.0[..31]);
    Uint256(bytes).to_decimal()
}

/// The signed result of an appraisal.
///
/// `engine_json` is the engine's output, `proof` the proof of its witness, `circuit_name` the circuit that made it,
/// `rules_hash` the engine's frozen rules hash and `encrypted_label` the label's envelope under the dataset key.
///
/// # Errors
///
/// [`ResultError`] if the engine output lacks what the result needs, if the engine hashed other bytes than the
/// registry's, or if the proof's public signals are not the circuit's twelve.
pub fn appraisal_result(
    facts: &JobFacts,
    rules_hash: &str,
    engine_json: &str,
    circuit_name: &str,
    proof: &Proof,
    encrypted_label: &str,
) -> Result<Value, ResultError> {
    let engine: Value =
        serde_json::from_str(engine_json).map_err(|_| ResultError::Engine("JSON"))?;
    if text(&engine["hashes"]["plaintext_hash"], "plaintext hash")?
        != field_of(&facts.plaintext_hash)
    {
        return Err(ResultError::PlaintextHash);
    }
    if proof.public_signals.len() != APPRAISAL_SIGNALS {
        return Err(ResultError::Signals(
            proof.public_signals.len(),
            APPRAISAL_SIGNALS,
        ));
    }
    let mut counts = Map::new();
    for name in COUNT_NAMES {
        let value = engine["witness"][name]
            .as_u64()
            .ok_or(ResultError::Engine("witness count"))?;
        counts.insert(name.to_owned(), json!(value));
    }
    let notes = engine["quality"]["flags"]
        .as_array()
        .ok_or(ResultError::Engine("quality flags"))?;
    let notes: Vec<Value> = notes
        .iter()
        .map(|n| {
            n.as_str()
                .map(|s| json!(s))
                .ok_or(ResultError::Engine("quality flag"))
        })
        .collect::<Result<_, _>>()?;
    let mut object = with_engine(base(facts, "appraisal"), facts);
    object.insert("rulesHash".into(), json!(rules_hash));
    object.insert("circuitName".into(), json!(circuit_name));
    object.insert("publicSignals".into(), json!(proof.public_signals));
    object.insert("proof".into(), json!(proof.text));
    object.insert(
        "circuitInputs".into(),
        json!(Value::Object(counts).to_string()),
    );
    object.insert("encryptedLabel".into(), json!(encrypted_label));
    object.insert(
        "labelHash".into(),
        json!(text(&engine["hashes"]["label_hash"], "label hash")?),
    );
    object.insert("qualityNotes".into(), Value::Array(notes));
    Ok(Value::Object(object))
}

/// Why a threshold check was not answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The group the check selects is too small to answer without revealing rows.
    SmallGroup,
    /// The engine could not count the check.
    UnusableCheck,
}

impl Refusal {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SmallGroup => "small_group",
            Self::UnusableCheck => "unusable_check",
        }
    }
}

/// What the engine's count of one check says about it: an answer to prove, or a refusal.
///
/// # Errors
///
/// [`ResultError::Engine`] if the count has no usable fields.
pub fn classify_count(count_json: &str) -> Result<Result<(u64, bool), Refusal>, ResultError> {
    let count: Value = serde_json::from_str(count_json).map_err(|_| ResultError::Engine("JSON"))?;
    if !count["error"].is_null() {
        return Ok(Err(Refusal::UnusableCheck));
    }
    if count["answerable"]
        .as_bool()
        .ok_or(ResultError::Engine("answerable"))?
    {
        let band = count["band"].as_u64().ok_or(ResultError::Engine("band"))?;
        let passed = count["passed"]
            .as_bool()
            .ok_or(ResultError::Engine("passed"))?;
        return Ok(Ok((band, passed)));
    }
    Ok(Err(Refusal::SmallGroup))
}

/// The signed result of one threshold check that was answered, with its proof.
///
/// # Errors
///
/// [`ResultError::Signals`] if the proof does not have the threshold circuit's seven public signals.
pub fn threshold_answer(
    facts: &JobFacts,
    label_hash: &str,
    check_hash: &Bytes32,
    band: u64,
    passed: bool,
    circuit_name: &str,
    proof: &Proof,
) -> Result<Value, ResultError> {
    if proof.public_signals.len() != THRESHOLD_SIGNALS {
        return Err(ResultError::Signals(
            proof.public_signals.len(),
            THRESHOLD_SIGNALS,
        ));
    }
    let mut object = with_engine(base(facts, "threshold"), facts);
    object.insert("labelHash".into(), json!(label_hash));
    object.insert("checkHash".into(), json!(check_hash.to_string()));
    object.insert("status".into(), json!("answered"));
    object.insert("band".into(), json!(band));
    object.insert("passed".into(), json!(passed));
    object.insert("circuitName".into(), json!(circuit_name));
    object.insert("publicSignals".into(), json!(proof.public_signals));
    object.insert("proof".into(), json!(proof.text));
    Ok(Value::Object(object))
}

/// The signed result of one threshold check that was refused.
#[must_use]
pub fn threshold_refusal(
    facts: &JobFacts,
    label_hash: &str,
    check_hash: &Bytes32,
    refusal: Refusal,
) -> Value {
    let mut object = with_engine(base(facts, "threshold"), facts);
    object.insert("labelHash".into(), json!(label_hash));
    object.insert("checkHash".into(), json!(check_hash.to_string()));
    object.insert("status".into(), json!("refused"));
    object.insert("reason".into(), json!(refusal.as_str()));
    Value::Object(object)
}

/// The signed result of a job that failed: the code and nothing else.
#[must_use]
pub fn error_result(job_id: &Bytes32, code: ErrorCode) -> Value {
    json!({"v": RESULT_VERSION, "kind": "error", "jobId": job_id.to_string(), "error": code.as_str()})
}

/// The result key's signature over a result, as `0x` and 130 hex digits.
///
/// # Errors
///
/// [`ResultError::Canonical`] if the result is not canonical JSON.
pub fn sign_result(result: &Value, key: &ResultKey) -> Result<String, ResultError> {
    Ok(format!(
        "0x{}",
        hex::encode(key.sign(&result_digest(result)?))
    ))
}

/// What the workload knows about a dispute job, the same for each result it posts.
#[derive(Debug, Clone)]
pub struct DisputeFacts {
    /// The job id.
    pub job_id: Bytes32,
    /// The dispute id, a decimal number.
    pub dispute_id: String,
    /// The workload identity the consent names.
    pub workload_identity: Bytes32,
    /// The appraisal family.
    pub family: String,
    /// The rules version.
    pub rules_version: String,
    /// The Digital Key token id.
    pub token_id: String,
    /// The dataset's registry id.
    pub dataset: String,
    /// The buyer's wallet, `0x` and 40 lower-case hex digits.
    pub buyer: String,
    /// The SHA-256 of the evidence plaintext, which the consent names and the workload checked.
    pub evidence_hash: Bytes32,
    /// The engine module's version.
    pub engine_version: String,
    /// The SHA-256 of the engine module that ran.
    pub engine_module_sha256: Bytes32,
}

fn dispute_base(facts: &DisputeFacts, dispute_type: &str) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("v".into(), json!(RESULT_VERSION));
    object.insert("kind".into(), json!("dispute"));
    object.insert("disputeType".into(), json!(dispute_type));
    object.insert("jobId".into(), json!(facts.job_id.to_string()));
    object.insert("disputeId".into(), json!(facts.dispute_id));
    object.insert("family".into(), json!(facts.family));
    object.insert("rulesVersion".into(), json!(facts.rules_version));
    object.insert(
        "workloadIdentity".into(),
        json!(facts.workload_identity.to_string()),
    );
    object.insert("tokenId".into(), json!(facts.token_id));
    object.insert("dataset".into(), json!(facts.dataset));
    object.insert("buyer".into(), json!(facts.buyer));
    object.insert(
        "evidenceHash".into(),
        json!(facts.evidence_hash.to_string()),
    );
    object.insert("engineVersion".into(), json!(facts.engine_version));
    object.insert(
        "engineModuleSha256".into(),
        json!(hex::encode(facts.engine_module_sha256.0)),
    );
    object
}

/// A field of the engine's output that must be present, as a string or null.
fn text_or_null(engine: &Value, name: &'static str) -> Result<Value, ResultError> {
    match engine.get(name) {
        Some(value @ (Value::String(_) | Value::Null)) => Ok(value.clone()),
        _ => Err(ResultError::Engine(name)),
    }
}

/// The signed result of a label dispute: what the engine's label check made of the evidence file. The hashes are the
/// engine's own (decimal field elements), which the API compares with the licence's proof; `error` is the engine's
/// reason when the label cannot be reproduced from the file.
///
/// # Errors
///
/// [`ResultError::Engine`] if the engine output lacks a field the result needs.
pub fn label_dispute_result(facts: &DisputeFacts, engine_json: &str) -> Result<Value, ResultError> {
    let engine: Value =
        serde_json::from_str(engine_json).map_err(|_| ResultError::Engine("JSON"))?;
    let mut object = dispute_base(facts, "label_mismatch");
    object.insert(
        "plaintextHash".into(),
        json!(text(&engine["plaintext_hash"], "plaintext hash")?),
    );
    object.insert("labelHash".into(), text_or_null(&engine, "label_hash")?);
    object.insert(
        "inputsCommitment".into(),
        text_or_null(&engine, "inputs_commitment")?,
    );
    object.insert("error".into(), text_or_null(&engine, "error")?);
    Ok(Value::Object(object))
}

/// The signed result of a threshold dispute: the band and pass the engine's count of the disputed check gives on the
/// evidence file, which the API compares with the answer given at the licence. `band` and `passed` are null when the
/// check could not be answered, with the engine's reason in `error` or not.
///
/// # Errors
///
/// [`ResultError::Engine`] if the engine output lacks a field the result needs.
pub fn threshold_dispute_result(
    facts: &DisputeFacts,
    check_hash: &Bytes32,
    count_json: &str,
) -> Result<Value, ResultError> {
    let count: Value = serde_json::from_str(count_json).map_err(|_| ResultError::Engine("JSON"))?;
    let band = match count.get("band") {
        Some(Value::Null) => Value::Null,
        Some(other) => json!(other.as_u64().ok_or(ResultError::Engine("band"))?),
        None => return Err(ResultError::Engine("band")),
    };
    let passed = match count.get("passed") {
        Some(Value::Null) => Value::Null,
        Some(other) => json!(other.as_bool().ok_or(ResultError::Engine("passed"))?),
        None => return Err(ResultError::Engine("passed")),
    };
    let mut object = dispute_base(facts, "false_threshold");
    object.insert("checkHash".into(), json!(check_hash.to_string()));
    object.insert(
        "plaintextHash".into(),
        json!(text(&count["plaintext_hash"], "plaintext hash")?),
    );
    object.insert("band".into(), band);
    object.insert("passed".into(), passed);
    object.insert("error".into(), text_or_null(&count, "error")?);
    Ok(Value::Object(object))
}
