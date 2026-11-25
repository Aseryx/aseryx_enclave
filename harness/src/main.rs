//! The workload's entry point: claim one job, run it, post the signed result, exit.
//!
//! Exit status 0 means the job's result was posted. 1 means the job failed and its signed error code was posted when the
//! API could be reached. 2 means the workload could not start, before any job was claimed.

use aseryx_enclave_harness::api::{ApiClient, ApiJobSource};
use aseryx_enclave_harness::attest::SidecarAttestor;
use aseryx_enclave_harness::chain::RpcChain;
use aseryx_enclave_harness::config::{Config, engine_memory_bytes, memory_gb};
use aseryx_enclave_harness::consent::Domain;
use aseryx_enclave_harness::engine::{EngineModule, Limits};
use aseryx_enclave_harness::job::{Services, run_job};
use aseryx_enclave_harness::lit::ApiRelay;
use aseryx_enclave_harness::prove::{ArkProver, BucketSource, parse_pins};
use aseryx_enclave_harness::store::{CipherCache, IpfsGateway};
use std::process::ExitCode;

const CGROUP_MEMORY_MAX: &str = "/sys/fs/cgroup/memory.max";
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
    let memory = match std::fs::read_to_string(CGROUP_MEMORY_MAX)
        .map_err(|_| aseryx_enclave_harness::config::ConfigError::Memory)
        .and_then(|text| memory_gb(&text))
    {
        Ok(memory) => memory,
        Err(error) => return start_failure("memory", error),
    };
    let engine_bytes = match std::fs::read(&config.engine_path) {
        Ok(bytes) => bytes,
        Err(error) => return start_failure("engine module", error),
    };
    let limits = Limits {
        deadline: config.engine_deadline,
        max_memory_bytes: engine_memory_bytes(memory),
    };
    let engine = match EngineModule::load(&engine_bytes, config.engine_sha256, limits) {
        Ok(engine) => engine,
        Err(error) => return start_failure("engine module", error),
    };
    drop(engine_bytes);
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
    let fetcher = IpfsGateway::new(&config.ipfs_gateway);
    let artifacts = BucketSource::new(&config.artifacts_url);
    let prover = ArkProver::new(pins, &artifacts);

    let services = Services {
        attestor: &attestor,
        source: &source,
        api: &api,
        releaser: &releaser,
        chain: &chain,
        fetcher: &fetcher,
        cache: &cache,
        engine: &engine,
        prover: &prover,
        engine_module_sha256: config.engine_sha256,
        domain,
        memory_gb: memory,
        parallel_fetches: config.parallel_fetches,
        appraisal_circuit: &config.appraisal_circuit,
    };
    match run_job(&services) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("job failed: {code}");
            ExitCode::from(1)
        }
    }
}
