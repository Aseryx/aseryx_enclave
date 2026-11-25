//! A dispute job: the buyer's evidence file and label are checked inside the workload.
//!
//! The buyer encrypted the file they were delivered and the label they hold under one fresh evidence key, sealed that key
//! to the decrypt action and signed a `DisputeJob` consent. The workload has the action release the evidence key (never
//! the provider's dataset key), fetches the ciphertext from the signed URLs the API gave it, checks the file against the
//! consent's evidence hash and the label against the licence's label hash, and runs the engine: a label check for a
//! label dispute, a threshold count of the disputed check for a threshold dispute. It signs what the engine found; the
//! API compares that with the licence's proof or answer and decides.

use super::{Services, read, release_key};
use crate::check::parse_check;
use crate::claim::Claimed;
use crate::consent::{Address, Bytes32, DisputeJob};
use crate::error_code::ErrorCode;
use crate::label::open_label;
use crate::manifest::Manifest;
use crate::metrics::Stage;
use crate::pipeline::{PipelineError, run_passes_recorded};
use crate::result::{DisputeFacts, label_dispute_result, threshold_dispute_result};
use crate::store::{StoreError, UrlChunks, chunk_limit};
use serde::Deserialize;
use serde_json::{Value, json};

const MAX_MANIFEST_BYTES: u64 = 1 << 20;
const MAX_LABEL_BYTES: u64 = 8 << 20;

/// What a dispute asks the workload to decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeType {
    /// The delivered file does not give the label the licence was sold under.
    LabelMismatch,
    /// The delivered file does not give the threshold answer the owner signed.
    FalseThreshold,
}

/// Where the encrypted evidence is: short-lived signed URLs, since the workload holds no storage credential.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    /// The evidence file's manifest.
    pub manifest_url: String,
    /// The evidence file's encrypted chunks, in the manifest's order.
    pub chunk_urls: Vec<String>,
    /// The label's envelope under the evidence key.
    pub label_url: String,
}

/// The disputed threshold check.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisputeCheck {
    /// The check's hash, as the owner's answer names it.
    pub check_hash: Bytes32,
    /// The check's conditions, as the engine reads them.
    pub conditions: Value,
    /// The share of rows allowed to fail, in permille.
    pub allowed_failure_permille: u32,
}

/// What the API's `job` action returns for a dispute.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisputeInputs {
    /// The typed consent the buyer signed.
    pub consent: Value,
    /// The buyer's signature over the consent.
    pub consent_signature: String,
    /// The appraisal family.
    pub family: String,
    /// The dispute id, a decimal number.
    pub dispute_id: String,
    /// What the dispute claims.
    pub dispute_type: DisputeType,
    /// The Digital Key token id.
    pub token_id: String,
    /// The dataset's registry id.
    pub dataset: String,
    /// The buyer's wallet.
    pub buyer: String,
    /// The evidence key, sealed to the decrypt action.
    pub evidence_sealed: Value,
    /// Where the encrypted evidence is.
    pub evidence: Evidence,
    /// The label hash the licence was sold under, a decimal field element.
    pub licence_label_hash: String,
    /// The disputed check, for a threshold dispute.
    #[serde(default)]
    pub check: Option<DisputeCheck>,
}

/// The consent, checked against the claim and the request.
struct Consent {
    digest: Bytes32,
    facts: DisputeFacts,
}

fn verify_consent(
    services: &Services<'_>,
    claimed: &Claimed,
    inputs: &DisputeInputs,
) -> Result<Consent, ErrorCode> {
    let c: DisputeJob = read(
        serde_json::from_value(inputs.consent.clone()),
        ErrorCode::KeyDenied,
    )?;
    let buyer = read(Address::parse(&inputs.buyer), ErrorCode::KeyDenied)?;
    let has_check = inputs.check.is_some();
    let wants_check = inputs.dispute_type == DisputeType::FalseThreshold;
    if c.job_id != claimed.job_id
        || c.dispute_id.to_decimal() != inputs.dispute_id
        || c.token_id.to_decimal() != inputs.token_id
        || c.dataset.as_str() != inputs.dataset
        || c.buyer != buyer
        || c.family.as_str() != inputs.family
        || has_check != wants_check
    {
        return Err(ErrorCode::KeyDenied);
    }
    let info = read(services.engine.info(), ErrorCode::AppraiseFailed)?;
    if info.family != inputs.family {
        return Err(ErrorCode::LabelMismatchEvidence);
    }
    Ok(Consent {
        digest: c.digest(services.domain),
        facts: DisputeFacts {
            job_id: c.job_id,
            dispute_id: inputs.dispute_id.clone(),
            workload_identity: c.workload_identity,
            family: inputs.family.clone(),
            rules_version: c.rules_version.as_str().to_owned(),
            token_id: inputs.token_id.clone(),
            dataset: inputs.dataset.clone(),
            buyer: format!("0x{}", hex::encode(buyer.0)),
            evidence_hash: c.evidence_hash,
            engine_version: info.version,
            engine_module_sha256: services.engine_module_sha256,
        },
    })
}

fn evidence_code(error: &PipelineError) -> ErrorCode {
    match error {
        PipelineError::Store(_) => ErrorCode::FetchFailed,
        PipelineError::Chunk | PipelineError::Size | PipelineError::HashMismatch => {
            ErrorCode::EvidenceMismatch
        }
        PipelineError::Engine(_) => ErrorCode::AppraiseFailed,
    }
}

/// The evidence file's manifest, bound to this dispute's token, dataset and evidence hash.
fn evidence_manifest(
    services: &Services<'_>,
    inputs: &DisputeInputs,
    facts: &DisputeFacts,
) -> Result<Manifest, ErrorCode> {
    let text = read(
        services
            .evidence
            .get(&inputs.evidence.manifest_url, MAX_MANIFEST_BYTES),
        ErrorCode::FetchFailed,
    )?;
    let manifest = read(
        Manifest::parse(&String::from_utf8_lossy(&text)),
        ErrorCode::EvidenceMismatch,
    )?;
    if manifest.token_id != inputs.token_id
        || manifest.dataset != inputs.dataset
        || manifest.plaintext_sha256 != facts.evidence_hash.0
    {
        return Err(ErrorCode::EvidenceMismatch);
    }
    Ok(manifest)
}

/// The buyer's label, opened with the evidence key and checked against the licence's label hash.
fn evidence_label(
    services: &Services<'_>,
    inputs: &DisputeInputs,
    key: &[u8; 32],
) -> Result<String, ErrorCode> {
    let envelope = read(
        services
            .evidence
            .get(&inputs.evidence.label_url, MAX_LABEL_BYTES),
        ErrorCode::FetchFailed,
    )?;
    let envelope = read(
        String::from_utf8(envelope),
        ErrorCode::LabelMismatchEvidence,
    )?;
    let label = read(open_label(&envelope, key), ErrorCode::LabelMismatchEvidence)?;
    let parsed: Value = read(
        serde_json::from_str(&label),
        ErrorCode::LabelMismatchEvidence,
    )?;
    if parsed["family"].as_str() != Some(inputs.family.as_str()) {
        return Err(ErrorCode::LabelMismatchEvidence);
    }
    let hash = read(
        services.engine.label_hash(&label),
        ErrorCode::LabelMismatchEvidence,
    )?;
    if hash != inputs.licence_label_hash {
        return Err(ErrorCode::LabelMismatchEvidence);
    }
    Ok(label)
}

/// The disputed check as the engine reads it, which must be the check the API named.
fn check_text(check: &DisputeCheck) -> Result<String, ErrorCode> {
    let text = json!({
        "conditions": check.conditions,
        "allowed_failure_permille": check.allowed_failure_permille,
    })
    .to_string();
    let parsed = read(parse_check(&text), ErrorCode::KeyDenied)?;
    if parsed.hash != check.check_hash {
        return Err(ErrorCode::KeyDenied);
    }
    Ok(text)
}

/// Runs a dispute job to its signed-result body: the consent, the evidence key, the evidence checks, the engine.
pub(super) fn run(
    services: &Services<'_>,
    claimed: &Claimed,
    inputs: &DisputeInputs,
) -> Result<Value, ErrorCode> {
    let consent = services
        .metrics
        .time(Stage::Checks, || verify_consent(services, claimed, inputs))?;
    let mut key = release_key(
        services,
        claimed,
        "evidenceSealed",
        &inputs.evidence_sealed,
        &consent.digest,
    )?;
    let outcome = check_evidence(services, inputs, &consent.facts, &key);
    key.fill(0);
    outcome
}

fn check_evidence(
    services: &Services<'_>,
    inputs: &DisputeInputs,
    facts: &DisputeFacts,
    key: &[u8; 32],
) -> Result<Value, ErrorCode> {
    let manifest = evidence_manifest(services, inputs, facts)?;
    let chunks = read(
        UrlChunks::new(
            &manifest.chunks,
            &inputs.evidence.chunk_urls,
            services.evidence,
        ),
        ErrorCode::FetchFailed,
    )?;
    match services
        .cache
        .ensure_room(manifest.chunks.len(), chunk_limit(manifest.chunk_size))
    {
        Ok(()) => {}
        Err(StoreError::NoRoom) => return Err(ErrorCode::TooLarge),
        Err(_) => return Err(ErrorCode::FetchFailed),
    }
    read(
        services.cache.fill(
            &manifest.chunks,
            &chunks,
            services.parallel_fetches,
            chunk_limit(manifest.chunk_size),
        ),
        ErrorCode::FetchFailed,
    )?;
    let label = evidence_label(services, inputs, key)?;
    let expected = facts.evidence_hash.0;
    match inputs.dispute_type {
        DisputeType::LabelMismatch => {
            let run = read(
                services.engine.label_check(&label),
                ErrorCode::AppraiseFailed,
            )?;
            let engine = run_passes_recorded(
                run,
                &manifest,
                key,
                services.cache,
                &expected,
                services.metrics,
            )
            .map_err(|e| evidence_code(&e))?;
            read(
                label_dispute_result(facts, &engine),
                ErrorCode::AppraiseFailed,
            )
        }
        DisputeType::FalseThreshold => {
            let check = inputs.check.as_ref().ok_or(ErrorCode::KeyDenied)?;
            let run = read(
                services.engine.threshold_count(&label, &check_text(check)?),
                ErrorCode::AppraiseFailed,
            )?;
            let count = run_passes_recorded(
                run,
                &manifest,
                key,
                services.cache,
                &expected,
                services.metrics,
            )
            .map_err(|e| evidence_code(&e))?;
            read(
                threshold_dispute_result(facts, &check.check_hash, &count),
                ErrorCode::AppraiseFailed,
            )
        }
    }
}
