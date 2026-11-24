//! Reading a dataset's registry record from the Digital Key contract.
//!
//! The workload takes the plaintext hash and the manifest from the chain, never from the API, so a dishonest API cannot
//! change what the file must hash to. Three independent endpoints are read; at least two must answer and every
//! endpoint that answers must agree.

use crate::consent::{Address, Bytes32, Uint256};
use serde::Deserialize;
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use std::time::Duration;

const GET_DATASET: &str = "getDataset(uint256,string)";
const FUJI_CHAIN_ID: &str = "0xa869";
const MIN_ANSWERS: usize = 2;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_MANIFEST_CID_BYTES: usize = 256;

/// Why a dataset record could not be read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChainError {
    /// The contract's answer is not an encoded record.
    #[error("the registry answer is malformed")]
    Malformed,
    /// No dataset is registered under that id.
    #[error("the dataset is not registered")]
    NotRegistered,
    /// The dataset was dropped by its owner.
    #[error("the dataset was dropped")]
    Dropped,
    /// Fewer than two endpoints answered.
    #[error("too few endpoints answered")]
    TooFewAnswers,
    /// Two endpoints answered differently.
    #[error("the endpoints disagree")]
    Disagree,
}

/// The registry entry of a dataset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetRecord {
    /// The full SHA-256 of the plaintext.
    pub plaintext_hash: Bytes32,
    /// The manifest's content identifier, without the `ipfs://` prefix.
    pub manifest_cid: String,
    /// The latest licence expiry ever granted, in seconds since the epoch.
    pub latest_expiry: u64,
}

/// Something that can read a dataset's registry entry.
pub trait ChainReader {
    /// The registry entry of `dataset` on `token_id`.
    ///
    /// # Errors
    ///
    /// A [`ChainError`] if the record cannot be read, is not registered or was dropped.
    fn get_dataset(&self, token_id: &Uint256, dataset: &str) -> Result<DatasetRecord, ChainError>;
}

fn word(value: usize) -> [u8; 32] {
    Uint256::from_u64(value as u64).0
}

/// The call data of `getDataset(tokenId, datasetId)`.
#[must_use]
pub fn encode_get_dataset(token_id: &Uint256, dataset: &str) -> Vec<u8> {
    let selector = Keccak256::digest(GET_DATASET.as_bytes());
    let mut out = selector[..4].to_vec();
    out.extend_from_slice(&token_id.0);
    out.extend_from_slice(&word(0x40));
    out.extend_from_slice(&word(dataset.len()));
    out.extend_from_slice(dataset.as_bytes());
    out.resize(out.len() + (32 - dataset.len() % 32) % 32, 0);
    out
}

fn read_word(raw: &[u8], at: usize) -> Result<&[u8], ChainError> {
    raw.get(at..at.checked_add(32).ok_or(ChainError::Malformed)?)
        .ok_or(ChainError::Malformed)
}

fn read_usize(raw: &[u8], at: usize) -> Result<usize, ChainError> {
    let bytes = read_word(raw, at)?;
    if bytes[..24].iter().any(|b| *b != 0) {
        return Err(ChainError::Malformed);
    }
    usize::try_from(u64::from_be_bytes(
        bytes[24..].try_into().map_err(|_| ChainError::Malformed)?,
    ))
    .map_err(|_| ChainError::Malformed)
}

/// Decodes the answer of `getDataset`: a struct of a hash, a string, an expiry and a flag.
///
/// # Errors
///
/// [`ChainError::Malformed`] for anything that is not exactly that encoding, [`ChainError::NotRegistered`] for the
/// all-zero record of an unknown id and [`ChainError::Dropped`] for a dropped dataset.
pub fn decode_dataset_record(raw: &[u8]) -> Result<DatasetRecord, ChainError> {
    let base = read_usize(raw, 0)?;
    let hash: [u8; 32] = read_word(raw, base)?
        .try_into()
        .map_err(|_| ChainError::Malformed)?;
    let string_at = base
        .checked_add(read_usize(raw, base + 32)?)
        .ok_or(ChainError::Malformed)?;
    let expiry = read_word(raw, base + 64)?;
    let flag = read_word(raw, base + 96)?;
    if expiry[..24].iter().any(|b| *b != 0) || flag[..31].iter().any(|b| *b != 0) || flag[31] > 1 {
        return Err(ChainError::Malformed);
    }
    let length = read_usize(raw, string_at)?;
    let start = string_at + 32;
    let cid = raw
        .get(start..start.checked_add(length).ok_or(ChainError::Malformed)?)
        .ok_or(ChainError::Malformed)?;
    if length > MAX_MANIFEST_CID_BYTES {
        return Err(ChainError::Malformed);
    }
    let manifest_cid = String::from_utf8(cid.to_vec()).map_err(|_| ChainError::Malformed)?;
    if hash == [0u8; 32] && manifest_cid.is_empty() {
        return Err(ChainError::NotRegistered);
    }
    if flag[31] == 1 {
        return Err(ChainError::Dropped);
    }
    Ok(DatasetRecord {
        plaintext_hash: Bytes32(hash),
        manifest_cid,
        latest_expiry: u64::from_be_bytes(
            expiry[24..].try_into().map_err(|_| ChainError::Malformed)?,
        ),
    })
}

#[derive(Deserialize)]
struct RpcReply {
    result: Option<String>,
}

/// The Digital Key contract read through several JSON-RPC endpoints.
pub struct RpcChain {
    contract: Address,
    urls: Vec<String>,
    agent: ureq::Agent,
}

impl RpcChain {
    /// A reader of `contract` through the given endpoints.
    #[must_use]
    pub fn new(contract: Address, urls: &[&str]) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            contract,
            urls: urls.iter().map(|u| (*u).to_owned()).collect(),
            agent,
        }
    }

    fn call(&self, url: &str, method: &str, params: &Value) -> Option<String> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut response = self.agent.post(url).send_json(&body).ok()?;
        if response.status().as_u16() != 200 {
            return None;
        }
        response.body_mut().read_json::<RpcReply>().ok()?.result
    }

    /// One endpoint's answer, or none when it fails, is on another chain or does not answer with data.
    fn answer(&self, url: &str, data: &[u8]) -> Option<Vec<u8>> {
        if !self
            .call(url, "eth_chainId", &json!([]))?
            .eq_ignore_ascii_case(FUJI_CHAIN_ID)
        {
            return None;
        }
        let to = format!("0x{}", hex::encode(self.contract.0));
        let result = self.call(
            url,
            "eth_call",
            &json!([{"to": to, "data": format!("0x{}", hex::encode(data))}, "latest"]),
        )?;
        hex::decode(result.strip_prefix("0x")?).ok()
    }
}

impl ChainReader for RpcChain {
    fn get_dataset(&self, token_id: &Uint256, dataset: &str) -> Result<DatasetRecord, ChainError> {
        let data = encode_get_dataset(token_id, dataset);
        let answers: Vec<Vec<u8>> = self
            .urls
            .iter()
            .filter_map(|url| self.answer(url, &data))
            .collect();
        if answers.len() < MIN_ANSWERS {
            return Err(ChainError::TooFewAnswers);
        }
        if answers.iter().any(|a| *a != answers[0]) {
            return Err(ChainError::Disagree);
        }
        decode_dataset_record(&answers[0])
    }
}
