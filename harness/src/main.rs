//! The workload's entry point: claim one job, run it, post the signed result, exit.
//!
//! Exit status 0 means the job's result was posted. 1 means the job failed and its signed error code was posted when the
//! API could be reached. 2 means the workload could not start, before any job was claimed.

use aseryx_enclave_harness::api::{ApiClient, ApiJobSource};
use aseryx_enclave_harness::attest::SidecarAttestor;
use aseryx_enclave_harness::chain::RpcChain;
use aseryx_enclave_harness::config::{
    Config, ConfigError, cgroup_limit_text, check_memory, mem_available_bytes,
    pass_two_budget_bytes,
};
use aseryx_enclave_harness::consent::Domain;
use aseryx_enclave_harness::engine::{Limits, NativeEngine};
use aseryx_enclave_harness::job::{Services, run_job};
use aseryx_enclave_harness::lit::ApiRelay;
use aseryx_enclave_harness::metrics::Recorder;
use aseryx_enclave_harness::prove::{ArkProver, BucketSource, parse_pins};
use aseryx_enclave_harness::store::{CipherCache, HttpFetcher, IpfsGateway};
use std::process::ExitCode;
use std::time::Duration;

const CGROUP_V2_MEMORY_MAX: &str = "/sys/fs/cgroup/memory.max";
const CGROUP_V1_MEMORY_LIMIT: &str = "/sys/fs/cgroup/memory/memory.limit_in_bytes";
const MEMINFO: &str = "/proc/meminfo";
/// How long past its deadline an engine run may stay open before the watchdog ends the process.
const ENGINE_HARD_GRACE: Duration = Duration::from_secs(120);
/// The circuits the workload proves with, by the SHA-256 of each artifact; part of the image, so part of the identity.
const CIRCUIT_PINS: &str = include_str!("../circuit-pins.json");

fn start_failure(what: &str, error: impl std::fmt::Display) -> ExitCode {
    eprintln!("cannot start: {what}: {error}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let config = match Config::from_lookup(&|name| std::env::var(name).ok()) {
        Ok(config) => config,
        Err(error) => return start_failure("settings", error),
    };
    let memory = config.memory_gb;
    let v2 = std::fs::read_to_string(CGROUP_V2_MEMORY_MAX).ok();
    let v1 = std::fs::read_to_string(CGROUP_V1_MEMORY_LIMIT).ok();
    if let Err(error) = cgroup_limit_text(v2.as_deref(), v1.as_deref())
        .and_then(|limit| check_memory(limit, memory))
    {
        return start_failure("memory", error);
    }
    let available = match std::fs::read_to_string(MEMINFO)
        .map_err(|_| ConfigError::Memory)
        .and_then(|text| mem_available_bytes(&text))
    {
        Ok(bytes) => bytes,
        Err(error) => return start_failure("memory", error),
    };
    let limits = Limits {
        deadline: config.engine_deadline,
        hard_grace: ENGINE_HARD_GRACE,
        pass_two_budget_bytes: pass_two_budget_bytes(memory, available),
    };
    let engine = match NativeEngine::new(config.engine_sha256, limits) {
        Ok(engine) => engine,
        Err(error) => return start_failure("engine", error),
    };
    let cache = match CipherCache::new(&config.cache_dir) {
        Ok(cache) => cache,
        Err(error) => return start_failure("cache", error),
    };
    let pins = match parse_pins(CIRCUIT_PINS) {
        Ok(pins) => pins,
        Err(error) => return start_failure("circuit pins", error),
    };
    let domain = match Domain::new(config.chain_id, config.registry) {
        Ok(domain) => domain,
        Err(error) => return start_failure("domain", error),
    };

    let attestor = SidecarAttestor::new(&config.sidecar_url, &config.maa_endpoint);
    let source = ApiJobSource::new(&config.api_url);
    let api = ApiClient::new(&config.api_url);
    let releaser = ApiRelay::new(&config.api_url);
    let urls: Vec<&str> = config.rpc_urls.iter().map(String::as_str).collect();
    let chain = RpcChain::new(config.registry, &urls);
    let gateways: Vec<&str> = config.ipfs_gateways.iter().map(String::as_str).collect();
    let fetcher = IpfsGateway::new(&gateways);
    let evidence = HttpFetcher::new();
    let artifacts = BucketSource::new(&config.artifacts_url);
    let prover = ArkProver::new(pins, &artifacts);

    let metrics = Recorder::new();
    let services = Services {
        attestor: &attestor,
        source: &source,
        api: &api,
        releaser: &releaser,
        chain: &chain,
        fetcher: &fetcher,
        evidence: &evidence,
        cache: &cache,
        engine: &engine,
        prover: &prover,
        engine_library_sha256: config.engine_sha256,
        domain,
        memory_gb: memory,
        parallel_fetches: config.parallel_fetches,
        appraisal_circuit: &config.appraisal_circuit,
        metrics: &metrics,
    };
    match run_job(&services) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("job failed: {code}");
            ExitCode::from(1)
        }
    }
}
