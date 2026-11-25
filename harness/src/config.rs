//! The workload's settings, read from environment variables.
//!
//! In a confidential container the environment is part of the policy the platform measures, so these settings are
//! covered by the workload identity the owner consents to. Every setting without a default must be present; a value
//! that is malformed is refused rather than replaced.

use crate::consent::{Address, Bytes32};
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_SIDECAR: &str = "http://localhost:8080";
const DEFAULT_MAA: &str = "sharedeus.eus.attest.azure.net";
const DEFAULT_ENGINE: &str = "/opt/enclave/engine.wasm";
const DEFAULT_CIRCUIT: &str = "tabular_appraisal_r7";
const DEFAULT_CACHE: &str = "/var/lib/enclave/cache";
const DEFAULT_PARALLEL: usize = 8;
const MAX_PARALLEL: usize = 64;
const DEFAULT_DEADLINE_SECS: u64 = 6 * 3600;
const MAX_RPC_URLS: usize = 8;
const GIB: u64 = 1 << 30;
/// How far under a whole number of gigabytes a container's memory limit may be and still count as that number, for the
/// platform's own use of the memory it is given.
const OVERHEAD_TOLERANCE: u64 = GIB / 5;
/// WebAssembly linear memory cannot exceed 4 GiB.
const WASM_MEMORY_LIMIT: u64 = 4 * GIB;

/// Why the settings could not be read.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// A required variable is not set.
    #[error("{0} is not set")]
    Missing(&'static str),
    /// A variable is set to something that is not valid for it.
    #[error("{0} is not valid")]
    Invalid(&'static str),
    /// The container's memory limit cannot be read as a whole number of gigabytes from 1 to 32.
    #[error("the container's memory limit is not usable")]
    Memory,
}

/// Everything the workload is told about its surroundings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The API's `attested-appraisal` function.
    pub api_url: String,
    /// The attestation sidecar of the container group.
    pub sidecar_url: String,
    /// The Azure Attestation host that issues the tokens.
    pub maa_endpoint: String,
    /// JSON-RPC endpoints that serve the Digital Key contract.
    pub rpc_urls: Vec<String>,
    /// The Digital Key contract.
    pub registry: Address,
    /// The chain the consents are signed for.
    pub chain_id: u64,
    /// The IPFS gateway.
    pub ipfs_gateway: String,
    /// The public circuit artifact bucket.
    pub artifacts_url: String,
    /// Where the engine module is in the image.
    pub engine_path: PathBuf,
    /// The SHA-256 the engine module must have.
    pub engine_sha256: Bytes32,
    /// The appraisal circuit's name.
    pub appraisal_circuit: String,
    /// Where the ciphertext chunks are cached.
    pub cache_dir: PathBuf,
    /// How many chunks are fetched at once.
    pub parallel_fetches: usize,
    /// How long an engine run may take.
    pub engine_deadline: Duration,
}

fn https(name: &'static str, value: &str) -> Result<String, ConfigError> {
    let host = value
        .strip_prefix("https://")
        .ok_or(ConfigError::Invalid(name))?;
    let usable = !host.is_empty() && value.bytes().all(|b| b.is_ascii_graphic());
    usable
        .then(|| value.to_owned())
        .ok_or(ConfigError::Invalid(name))
}

fn loopback(name: &'static str, value: &str) -> Result<String, ConfigError> {
    let rest = value
        .strip_prefix("http://")
        .ok_or(ConfigError::Invalid(name))?;
    let host = rest.split([':', '/']).next().unwrap_or_default();
    (matches!(host, "localhost" | "127.0.0.1") && value.bytes().all(|b| b.is_ascii_graphic()))
        .then(|| value.to_owned())
        .ok_or(ConfigError::Invalid(name))
}

fn name_of(name: &'static str, value: &str) -> Result<String, ConfigError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    valid
        .then(|| value.to_owned())
        .ok_or(ConfigError::Invalid(name))
}

fn number<T: std::str::FromStr>(name: &'static str, value: &str) -> Result<T, ConfigError> {
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ConfigError::Invalid(name));
    }
    value.parse().map_err(|_| ConfigError::Invalid(name))
}

impl Config {
    /// Reads the settings through `get`, which returns a variable's value.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first variable that is missing or malformed.
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let required = |name: &'static str| get(name).ok_or(ConfigError::Missing(name));
        let optional =
            |name: &'static str, default: &str| get(name).unwrap_or_else(|| default.to_owned());

        let rpc_urls = required("ENCLAVE_RPC_URLS")?
            .split(',')
            .map(|u| https("ENCLAVE_RPC_URLS", u))
            .collect::<Result<Vec<_>, _>>()?;
        if rpc_urls.len() > MAX_RPC_URLS {
            return Err(ConfigError::Invalid("ENCLAVE_RPC_URLS"));
        }
        let parallel_fetches: usize = number(
            "ENCLAVE_PARALLEL_FETCHES",
            &optional("ENCLAVE_PARALLEL_FETCHES", &DEFAULT_PARALLEL.to_string()),
        )?;
        if !(1..=MAX_PARALLEL).contains(&parallel_fetches) {
            return Err(ConfigError::Invalid("ENCLAVE_PARALLEL_FETCHES"));
        }
        let deadline: u64 = number(
            "ENCLAVE_ENGINE_DEADLINE_SECS",
            &optional(
                "ENCLAVE_ENGINE_DEADLINE_SECS",
                &DEFAULT_DEADLINE_SECS.to_string(),
            ),
        )?;
        if deadline == 0 {
            return Err(ConfigError::Invalid("ENCLAVE_ENGINE_DEADLINE_SECS"));
        }
        let chain_id: u64 = number("ENCLAVE_CHAIN_ID", &required("ENCLAVE_CHAIN_ID")?)?;
        if chain_id == 0 {
            return Err(ConfigError::Invalid("ENCLAVE_CHAIN_ID"));
        }
        Ok(Self {
            api_url: https("ENCLAVE_API_URL", &required("ENCLAVE_API_URL")?)?,
            sidecar_url: loopback(
                "ENCLAVE_SIDECAR_URL",
                &optional("ENCLAVE_SIDECAR_URL", DEFAULT_SIDECAR),
            )?,
            maa_endpoint: name_of(
                "ENCLAVE_MAA_ENDPOINT",
                &optional("ENCLAVE_MAA_ENDPOINT", DEFAULT_MAA),
            )?,
            rpc_urls,
            registry: Address::parse(&required("ENCLAVE_REGISTRY")?)
                .map_err(|_| ConfigError::Invalid("ENCLAVE_REGISTRY"))?,
            chain_id,
            ipfs_gateway: https("ENCLAVE_IPFS_GATEWAY", &required("ENCLAVE_IPFS_GATEWAY")?)?,
            artifacts_url: https("ENCLAVE_ARTIFACTS_URL", &required("ENCLAVE_ARTIFACTS_URL")?)?,
            engine_path: PathBuf::from(optional("ENCLAVE_ENGINE_PATH", DEFAULT_ENGINE)),
            engine_sha256: Bytes32::parse(&required("ENCLAVE_ENGINE_SHA256")?)
                .map_err(|_| ConfigError::Invalid("ENCLAVE_ENGINE_SHA256"))?,
            appraisal_circuit: name_of(
                "ENCLAVE_APPRAISAL_CIRCUIT",
                &optional("ENCLAVE_APPRAISAL_CIRCUIT", DEFAULT_CIRCUIT),
            )?,
            cache_dir: PathBuf::from(optional("ENCLAVE_CACHE_DIR", DEFAULT_CACHE)),
            parallel_fetches,
            engine_deadline: Duration::from_secs(deadline),
        })
    }
}

/// The container's memory in whole gigabytes, from the text of the cgroup's `memory.max`: the limit rounded down after
/// adding 0.2 GiB, so a 2 GB container that reports a little under 2 GiB is 2 GB and not 1.
///
/// # Errors
///
/// [`ConfigError::Memory`] for `max` (no limit), text that is not a number, or a limit that is not between 1 and 32 GB.
pub fn memory_gb(cgroup_memory_max: &str) -> Result<u32, ConfigError> {
    let bytes: u64 =
        number("memory.max", cgroup_memory_max.trim()).map_err(|_| ConfigError::Memory)?;
    u32::try_from(bytes.saturating_add(OVERHEAD_TOLERANCE) / GIB)
        .ok()
        .filter(|gb| (1..=32).contains(gb))
        .ok_or(ConfigError::Memory)
}

/// The most linear memory the engine may hold: three quarters of the container's, and never more than WebAssembly
/// allows, so the harness, the cache's page use and the prover keep the rest.
#[must_use]
pub fn engine_memory_bytes(memory_gb: u32) -> usize {
    let bytes = (u64::from(memory_gb) * GIB / 4 * 3).min(WASM_MEMORY_LIMIT);
    usize::try_from(bytes).unwrap_or(usize::MAX)
}
