//! Running one job from claim to signed result.
//!
//! The steps, each with the code the workload reports if it fails: claim a job with two attestations; fetch the job's
//! inputs from the API; check the consent against the chain registry; have the decrypt action release the dataset key to
//! this attested workload; fetch and cache the encrypted chunks; run the engine over them, checking the plaintext hash on
//! every pass; prove; sign; post. Nothing but the signed result leaves the workload.

use crate::attest::Attestor;
use crate::chain::ChainReader;
use crate::check::parse_check;
use crate::claim::{Claimed, JobSource, claim_job};
use crate::consent::{AppraisalJob, Bytes32, Domain, ThresholdJob, Uint256};
use crate::engine::{EngineModule, Run};
use crate::error_code::ErrorCode;
use crate::label::{open_label, seal_label};
use crate::lit::{KeyReleaser, open_attested_response};
use crate::manifest::Manifest;
use crate::pipeline::{run_passes, run_passes_many};
use crate::result::{
    JobFacts, Proof, appraisal_result, classify_count, error_result, sign_result, threshold_answer,
    threshold_refusal,
};
use crate::store::{CipherCache, Fetcher};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde_json::{Value, json};

/// The kinds of job this workload runs. Disputes run here in a later phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    /// Appraise a dataset and prove the appraisal.
    Appraisal,
    /// Answer threshold checks over a dataset.
    Threshold,
}

/// One threshold check to answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSpec {
    /// The check's hash, as the consent names it.
    pub check_hash: Bytes32,
    /// The check as the engine reads it: `{"conditions":[...],"allowed_failure_permille":n}`.
    pub check_json: String,
    /// The number of conditions, which picks the threshold circuit.
    pub conditions: u32,
    /// The share of rows allowed to fail, in permille.
    pub allowed_failure_permille: u32,
}

/// What the API's `job` action returns.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobInputs {
    /// The kind of job.
    pub kind: JobKind,
    /// The typed consent the owner signed.
    pub consent: Value,
    /// The owner's signature over the consent.
    pub consent_signature: String,
    /// The Digital Key token id.
    pub token_id: String,
    /// The dataset's registry id.
    pub dataset: String,
    /// The manifest's content identifier.
    pub manifest_cid: String,
    /// The appraisal family.
    pub family: String,
    /// Threshold jobs: the checks, in the consent's order.
    #[serde(default)]
    pub checks: Vec<CheckSpec>,
    /// Threshold jobs: the data label's envelope under the dataset key.
    #[serde(default)]
    pub encrypted_label: Option<String>,
}

/// Why the API could not be asked or did not answer.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
#[error("the API did not answer")]
pub struct ApiError;

/// The API's `attested-appraisal` function, after a job is claimed.
pub trait JobApi {
    /// The inputs of the claimed job, authenticated by token 2.
    ///
    /// # Errors
    ///
    /// [`ApiError`] if the API refuses or does not answer.
    fn job(&self, token: &str, runtime_data: &str) -> Result<JobInputs, ApiError>;

    /// Posts a result body (`action`, `token` and `runtimeData` are added by the caller).
    ///
    /// # Errors
    ///
    /// [`ApiError`] if the API refuses or does not answer.
    fn post_result(&self, body: &Value) -> Result<(), ApiError>;
}

/// Why a proof could not be made.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
#[error("the proof could not be made")]
pub struct ProveError;

/// Makes Groth16 proofs of the engine's witnesses with the pinned circuit artifacts.
pub trait Prover {
    /// The proof of `witness_json` for the circuit named `circuit`.
    ///
    /// # Errors
    ///
    /// [`ProveError`] if the circuit is unknown or the proof cannot be made.
    fn prove(&self, circuit: &str, witness_json: &str) -> Result<Proof, ProveError>;
}

/// Everything a job needs from the outside.
pub struct Services<'a> {
    /// Obtains attestation tokens.
    pub attestor: &'a dyn Attestor,
    /// Claims a job.
    pub source: &'a dyn JobSource,
    /// Fetches the job's inputs and posts its result.
    pub api: &'a dyn JobApi,
    /// Runs the decrypt action.
    pub releaser: &'a dyn KeyReleaser,
    /// Reads the dataset registry.
    pub chain: &'a dyn ChainReader,
    /// Fetches the manifest and the chunks.
    pub fetcher: &'a dyn Fetcher,
    /// Holds the ciphertext chunks.
    pub cache: &'a CipherCache,
    /// The appraisal engine.
    pub engine: &'a EngineModule,
    /// Makes proofs.
    pub prover: &'a dyn Prover,
    /// The SHA-256 of the engine module that runs, as the pin has it.
    pub engine_module_sha256: Bytes32,
    /// The chain and contract the consents are signed for.
    pub domain: Domain,
    /// The memory the container can see, in gigabytes.
    pub memory_gb: u32,
    /// How many chunks to fetch at once.
    pub parallel_fetches: usize,
    /// The name of the appraisal circuit, for example `tabular_appraisal_r7`.
    pub appraisal_circuit: &'a str,
}

fn read<T>(outcome: Result<T, impl std::fmt::Debug>, code: ErrorCode) -> Result<T, ErrorCode> {
    outcome.map_err(|_| code)
}

/// A job's typed consent and the facts every result repeats.
struct Verified {
    digest: Bytes32,
    facts: JobFacts,
    manifest: Manifest,
    label_hash: Option<String>,
}

/// The checks the API listed are the checks the owner signed, in the owner's order: each check's text hashes to the
/// hash in the consent, and the counts the API gives with it are the check's own.
fn check_specs(inputs: &JobInputs, signed: &[Bytes32]) -> Result<(), ErrorCode> {
    if inputs.checks.len() != signed.len() {
        return Err(ErrorCode::KeyDenied);
    }
    for (spec, hash) in inputs.checks.iter().zip(signed) {
        let parsed = read(parse_check(&spec.check_json), ErrorCode::KeyDenied)?;
        let same_check = parsed.hash == *hash && spec.check_hash == *hash;
        if !same_check
            || parsed.conditions != spec.conditions
            || parsed.allowed_failure_permille != spec.allowed_failure_permille
        {
            return Err(ErrorCode::KeyDenied);
        }
    }
    Ok(())
}

/// Parses the consent for the job's kind and checks it against the claim, the request and the registry.
fn verify_consent(
    services: &Services<'_>,
    claimed: &Claimed,
    inputs: &JobInputs,
) -> Result<Verified, ErrorCode> {
    let (
        digest,
        token_id,
        dataset,
        plaintext_hash,
        manifest_cid,
        family,
        rules_version,
        workload,
        job_id,
        label_hash,
        checks,
    ) = match inputs.kind {
        JobKind::Appraisal => {
            let c: AppraisalJob = read(
                serde_json::from_value(inputs.consent.clone()),
                ErrorCode::KeyDenied,
            )?;
            (
                c.digest(services.domain),
                c.token_id,
                c.dataset,
                c.plaintext_hash,
                c.manifest_cid,
                c.family,
                c.rules_version,
                c.workload_identity,
                c.job_id,
                None,
                Vec::new(),
            )
        }
        JobKind::Threshold => {
            let c: ThresholdJob = read(
                serde_json::from_value(inputs.consent.clone()),
                ErrorCode::KeyDenied,
            )?;
            let hashes = c.check_hashes.as_slice().to_vec();
            (
                c.digest(services.domain),
                c.token_id,
                c.dataset,
                c.plaintext_hash,
                c.manifest_cid,
                c.family,
                c.rules_version,
                c.workload_identity,
                c.job_id,
                Some(c.label_hash.to_decimal()),
                hashes,
            )
        }
    };
    if job_id != claimed.job_id
        || token_id.to_decimal() != inputs.token_id
        || dataset.as_str() != inputs.dataset
        || manifest_cid.as_str() != inputs.manifest_cid
        || family.as_str() != inputs.family
    {
        return Err(ErrorCode::KeyDenied);
    }
    if inputs.kind == JobKind::Threshold {
        check_specs(inputs, &checks)?;
    }
    let record = read(
        services.chain.get_dataset(&token_id, dataset.as_str()),
        ErrorCode::FetchFailed,
    )?;
    if record.plaintext_hash != plaintext_hash || record.manifest_cid != manifest_cid.as_str() {
        return Err(ErrorCode::HashMismatch);
    }
    let manifest_text = read(
        services.fetcher.fetch(&record.manifest_cid),
        ErrorCode::FetchFailed,
    )?;
    let manifest = read(
        Manifest::parse(&String::from_utf8_lossy(&manifest_text)),
        ErrorCode::HashMismatch,
    )?;
    if manifest.token_id != inputs.token_id
        || manifest.dataset != inputs.dataset
        || manifest.plaintext_sha256 != record.plaintext_hash.0
    {
        return Err(ErrorCode::HashMismatch);
    }
    let info = read(services.engine.info(), ErrorCode::AppraiseFailed)?;
    let facts = JobFacts {
        job_id,
        workload_identity: workload,
        family: inputs.family.clone(),
        rules_version: rules_version.as_str().to_owned(),
        token_id: inputs.token_id.clone(),
        dataset: inputs.dataset.clone(),
        manifest_cid: record.manifest_cid,
        plaintext_hash: record.plaintext_hash,
        engine_version: info.version,
        engine_module_sha256: services.engine_module_sha256,
    };
    Ok(Verified {
        digest,
        facts,
        manifest,
        label_hash,
    })
}

/// A token for the claimed job's runtime data that the API still accepts. The API refuses a token older than its limit,
/// and a job can run longer than that, so each call after the first asks the sidecar for a new one.
fn fresh_token(services: &Services<'_>, claimed: &Claimed) -> Result<String, ErrorCode> {
    read(
        services.attestor.attest(&claimed.runtime_data),
        ErrorCode::AttestationFailed,
    )
}

/// Has the decrypt action release the dataset key to this workload and opens it.
fn release_key(
    services: &Services<'_>,
    claimed: &Claimed,
    verified: &Verified,
) -> Result<[u8; 32], ErrorCode> {
    // The API builds every other parameter of the action from the job's own record; only the sealed key is the container's.
    let request = json!({
        "action": "decrypt",
        "token": fresh_token(services, claimed)?,
        "runtimeData": STANDARD.encode(claimed.runtime_data.to_bytes()),
        "sealed": verified.manifest.key_wrap,
    });
    let sealed = read(services.releaser.release(&request), ErrorCode::KeyDenied)?;
    read(
        open_attested_response(&claimed.response_key, &sealed, &verified.digest),
        ErrorCode::KeyDenied,
    )
}

fn prove(services: &Services<'_>, circuit: &str, witness: &str) -> Result<Proof, ErrorCode> {
    read(
        services.prover.prove(circuit, witness),
        ErrorCode::ProveFailed,
    )
}

fn appraise(
    services: &Services<'_>,
    verified: &Verified,
    key: &[u8; 32],
) -> Result<Vec<Value>, ErrorCode> {
    let mut salt = [0u8; 32];
    read(getrandom::fill(&mut salt), ErrorCode::AppraiseFailed)?;
    let manifest = &verified.manifest;
    let run: Run = read(
        services.engine.appraisal(
            &manifest.upload_name,
            &manifest.file_type,
            Some(&hex::encode(salt)),
            Some(&verified.facts.manifest_cid),
        ),
        ErrorCode::AppraiseFailed,
    )?;
    let engine_json = run_passes(
        run,
        manifest,
        key,
        services.cache,
        &verified.facts.plaintext_hash.0,
    )
    .map_err(|e| e.code())?;
    let engine: Value = read(
        serde_json::from_str(&engine_json),
        ErrorCode::AppraiseFailed,
    )?;
    let label = read(
        serde_json::to_string(&engine["label"]),
        ErrorCode::AppraiseFailed,
    )?;
    let envelope = read(seal_label(&label, key), ErrorCode::AppraiseFailed)?;
    let proof = prove(
        services,
        services.appraisal_circuit,
        &engine["witness"].to_string(),
    )?;
    let rules_hash = read(services.engine.info(), ErrorCode::AppraiseFailed)?.rules_hash;
    let result = read(
        appraisal_result(
            &verified.facts,
            &rules_hash,
            &engine_json,
            services.appraisal_circuit,
            &proof,
            &envelope,
        ),
        ErrorCode::AppraiseFailed,
    )?;
    Ok(vec![result])
}

fn threshold(
    services: &Services<'_>,
    inputs: &JobInputs,
    verified: &Verified,
    key: &[u8; 32],
) -> Result<Vec<Value>, ErrorCode> {
    let envelope = inputs
        .encrypted_label
        .as_deref()
        .ok_or(ErrorCode::HashMismatch)?;
    let label = read(open_label(envelope, key), ErrorCode::HashMismatch)?;
    let consent_label_hash = verified
        .label_hash
        .as_deref()
        .ok_or(ErrorCode::HashMismatch)?;
    if read(services.engine.label_hash(&label), ErrorCode::HashMismatch)? != consent_label_hash {
        return Err(ErrorCode::HashMismatch);
    }
    let runs = inputs
        .checks
        .iter()
        .map(|spec| services.engine.threshold_count(&label, &spec.check_json))
        .collect::<Result<Vec<_>, _>>();
    let runs = read(runs, ErrorCode::AppraiseFailed)?;
    let counts = run_passes_many(
        runs,
        &verified.manifest,
        key,
        services.cache,
        &verified.facts.plaintext_hash.0,
    )
    .map_err(|e| e.code())?;
    let revision = read(
        services.engine.threshold_circuit_revision(),
        ErrorCode::AppraiseFailed,
    )?;
    inputs
        .checks
        .iter()
        .zip(&counts)
        .map(|(spec, count)| {
            threshold_for(
                services,
                verified,
                consent_label_hash,
                spec,
                count,
                revision,
            )
        })
        .collect()
}

fn threshold_for(
    services: &Services<'_>,
    verified: &Verified,
    label_hash: &str,
    spec: &CheckSpec,
    count: &str,
    revision: u32,
) -> Result<Value, ErrorCode> {
    match read(classify_count(count), ErrorCode::AppraiseFailed)? {
        Err(refusal) => Ok(threshold_refusal(
            &verified.facts,
            label_hash,
            &spec.check_hash,
            refusal,
        )),
        Ok((band, passed)) => {
            let check_hash = Uint256(spec.check_hash.0).to_decimal();
            let witness = read(
                services.engine.threshold_witness(
                    count,
                    &check_hash,
                    spec.allowed_failure_permille,
                ),
                ErrorCode::AppraiseFailed,
            )?;
            let circuit = format!("threshold_r{revision}_c{}", spec.conditions);
            let proof = prove(services, &circuit, &witness)?;
            read(
                threshold_answer(
                    &verified.facts,
                    label_hash,
                    &spec.check_hash,
                    band,
                    passed,
                    &circuit,
                    &proof,
                ),
                ErrorCode::AppraiseFailed,
            )
        }
    }
}

/// Everything after the claim, up to the results ready to be signed and posted.
fn execute(services: &Services<'_>, claimed: &Claimed) -> Result<(Vec<Value>, JobKind), ErrorCode> {
    let runtime = STANDARD.encode(claimed.runtime_data.to_bytes());
    let inputs = read(
        services.api.job(&claimed.token, &runtime),
        ErrorCode::FetchFailed,
    )?;
    let verified = verify_consent(services, claimed, &inputs)?;
    let mut key = release_key(services, claimed, &verified)?;
    let outcome = (|| {
        read(
            services.cache.fill(
                &verified.manifest.chunks,
                services.fetcher,
                services.parallel_fetches,
            ),
            ErrorCode::FetchFailed,
        )?;
        match inputs.kind {
            JobKind::Appraisal => appraise(services, &verified, &key),
            JobKind::Threshold => threshold(services, &inputs, &verified, &key),
        }
    })();
    key.fill(0);
    Ok((outcome?, inputs.kind))
}

fn post(
    services: &Services<'_>,
    claimed: &Claimed,
    kind: JobKind,
    results: &[Value],
) -> Result<(), ErrorCode> {
    let runtime = STANDARD.encode(claimed.runtime_data.to_bytes());
    let signed = results
        .iter()
        .map(|r| {
            sign_result(r, &claimed.result_key)
                .map(|signature| json!({"result": r, "signature": signature}))
        })
        .collect::<Result<Vec<_>, _>>();
    let signed = read(signed, ErrorCode::UploadFailed)?;
    let token = fresh_token(services, claimed)?;
    let mut body = json!({"action": "result", "token": token, "runtimeData": runtime});
    match kind {
        JobKind::Appraisal => {
            body["kind"] = json!("appraisal");
            body["result"] = signed[0]["result"].clone();
            body["signature"] = signed[0]["signature"].clone();
        }
        JobKind::Threshold => {
            body["kind"] = json!("threshold");
            body["results"] = Value::Array(signed);
        }
    }
    read(services.api.post_result(&body), ErrorCode::UploadFailed)
}

fn post_error(services: &Services<'_>, claimed: &Claimed, code: ErrorCode) {
    let result = error_result(&claimed.job_id, code);
    if let (Ok(signature), Ok(token)) = (
        sign_result(&result, &claimed.result_key),
        fresh_token(services, claimed),
    ) {
        let runtime = STANDARD.encode(claimed.runtime_data.to_bytes());
        let body = json!({"action": "result", "token": token, "runtimeData": runtime, "kind": "error", "result": result, "signature": signature});
        let _ = services.api.post_result(&body);
    }
}

/// Runs one job: claims it, carries it out and posts the signed result, or the signed error code.
///
/// # Errors
///
/// The [`ErrorCode`] of the first step that failed. When the claim succeeded, that code was also posted as a signed error
/// result, best effort.
pub fn run_job(services: &Services<'_>) -> Result<(), ErrorCode> {
    let claimed = claim_job(services.attestor, services.source, services.memory_gb)?;
    let outcome = execute(services, &claimed)
        .and_then(|(results, kind)| post(services, &claimed, kind, &results));
    if let Err(code) = outcome {
        post_error(services, &claimed, code);
        return Err(code);
    }
    Ok(())
}
