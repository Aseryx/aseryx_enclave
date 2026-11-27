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
const DEFAULT_CIRCUIT: &str = "tabular_appraisal_r7";
const DEFAULT_CACHE: &str = "/var/lib/enclave/cache";
const DEFAULT_PARALLEL: usize = 8;
const MAX_PARALLEL: usize = 64;
const DEFAULT_DEADLINE_SECS: u64 = 6 * 3600;
const MAX_RPC_URLS: usize = 8;
const MAX_GATEWAYS: usize = 4;
const GIB: u64 = 1 << 30;
/// The share of the configured memory the container's cgroup must show, in percent: the platform keeps some of what a
/// container is sold, and a gigabyte may be decimal.
const MEMORY_FLOOR_PERCENT: u64 = 85;
/// The most memory pass 2 of an appraisal is given for its duplicate counts.
const MAX_PASS_TWO_BUDGET: u64 = GIB;
/// The least it is given: a smaller budget only adds readings of the file.
const MIN_PASS_TWO_BUDGET: u64 = 256 * (1 << 20);

/// Why the settings could not be read.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// A required variable is not set.
    #[error("{0} is not set")]
    Missing(&'static str),
    /// A variable is set to something that is not valid for it.
    #[error("{0} is not valid")]
    Invalid(&'static str),
    /// The cgroup shows less memory than the container is configured to have, or cannot be read.
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
    /// The IPFS gateways, tried in order.
    pub ipfs_gateways: Vec<String>,
    /// The public circuit artifact bucket.
    pub artifacts_url: String,
    /// The SHA-256 the engine library linked into this build must have.
    pub engine_sha256: Bytes32,
    /// The appraisal circuit's name.
    pub appraisal_circuit: String,
    /// Where the ciphertext chunks are cached.
    pub cache_dir: PathBuf,
    /// The container's memory in whole gigabytes, which the workload claims jobs with.
    pub memory_gb: u32,
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
        let ipfs_gateways = required("ENCLAVE_IPFS_GATEWAYS")?
            .split(',')
            .map(|u| https("ENCLAVE_IPFS_GATEWAYS", u))
            .collect::<Result<Vec<_>, _>>()?;
        if ipfs_gateways.len() > MAX_GATEWAYS {
            return Err(ConfigError::Invalid("ENCLAVE_IPFS_GATEWAYS"));
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
        let memory_gb: u32 = number("ENCLAVE_MEMORY_GB", &required("ENCLAVE_MEMORY_GB")?)?;
        if !(1..=32).contains(&memory_gb) {
            return Err(ConfigError::Invalid("ENCLAVE_MEMORY_GB"));
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
            ipfs_gateways,
            artifacts_url: https("ENCLAVE_ARTIFACTS_URL", &required("ENCLAVE_ARTIFACTS_URL")?)?,
            engine_sha256: Bytes32::parse(&required("ENCLAVE_ENGINE_SHA256")?)
                .map_err(|_| ConfigError::Invalid("ENCLAVE_ENGINE_SHA256"))?,
            appraisal_circuit: name_of(
                "ENCLAVE_APPRAISAL_CIRCUIT",
                &optional("ENCLAVE_APPRAISAL_CIRCUIT", DEFAULT_CIRCUIT),
            )?,
            cache_dir: PathBuf::from(optional("ENCLAVE_CACHE_DIR", DEFAULT_CACHE)),
            memory_gb,
            parallel_fetches,
            engine_deadline: Duration::from_secs(deadline),
        })
    }
}

/// A cgroup limit of this many bytes or more is no limit: a cgroup v1 memory controller with no limit reports a value
/// near 2^63.
const NO_LIMIT_BYTES: u64 = 1 << 62;

/// The text of the container's memory limit: the cgroup v2 `memory.max` when that file exists, otherwise the cgroup v1
/// `memory.limit_in_bytes`. Azure Container Instances confidential containers run cgroup v1.
///
/// # Errors
///
/// [`ConfigError::Memory`] when neither file could be read.
pub fn cgroup_limit_text<'a>(
    v2_memory_max: Option<&'a str>,
    v1_limit_in_bytes: Option<&'a str>,
) -> Result<&'a str, ConfigError> {
    v2_memory_max
        .or(v1_limit_in_bytes)
        .ok_or(ConfigError::Memory)
}

/// Checks the container's memory against its configured size, from the text of the cgroup's limit: the cgroup must show
/// at least 85% of `configured_gb` gibibytes, so the size the workload claims jobs with is the size it has.
///
/// # Errors
///
/// [`ConfigError::Memory`] for `max` or a value of 2^62 bytes or more (no limit), text that is not a number, or a limit
/// under 85% of the configured size.
pub fn check_memory(cgroup_limit: &str, configured_gb: u32) -> Result<(), ConfigError> {
    let bytes: u64 =
        number("memory limit", cgroup_limit.trim()).map_err(|_| ConfigError::Memory)?;
    let floor = u64::from(configured_gb) * GIB / 100 * MEMORY_FLOOR_PERCENT;
    (floor..NO_LIMIT_BYTES)
        .contains(&bytes)
        .then_some(())
        .ok_or(ConfigError::Memory)
}

/// The memory the kernel reports as available, in bytes, from the text of `/proc/meminfo`.
///
/// # Errors
///
/// [`ConfigError::Memory`] when there is no `MemAvailable` line in kilobytes.
pub fn mem_available_bytes(meminfo: &str) -> Result<u64, ConfigError> {
    let line = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .ok_or(ConfigError::Memory)?;
    let kilobytes = line
        .trim()
        .strip_suffix("kB")
        .ok_or(ConfigError::Memory)?
        .trim();
    let kilobytes: u64 = number("MemAvailable", kilobytes).map_err(|_| ConfigError::Memory)?;
    kilobytes.checked_mul(1024).ok_or(ConfigError::Memory)
}

/// The memory pass 2 of an appraisal may hold for its duplicate counts: half of the memory the container has, the smaller
/// of its configured size and what the kernel reports as available at start, at most 1 GiB and at least 256 MiB. The engine holds about a third more than its budget at its peak, and the
/// harness, the cache's page use and the prover keep the rest. A file whose row keys need more than the budget is read
/// once more for each slice, and every result is the same for any budget.
#[must_use]
pub fn pass_two_budget_bytes(memory_gb: u32, available_bytes: u64) -> u64 {
    let usable = (u64::from(memory_gb) * GIB).min(available_bytes);
    (usable / 2).clamp(MIN_PASS_TWO_BUDGET, MAX_PASS_TWO_BUDGET)
}
