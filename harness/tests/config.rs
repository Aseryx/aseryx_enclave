//! The settings: what is required, the defaults, and what is refused.

use aseryx_enclave_harness::config::{
    Config, ConfigError, cgroup_limit_text, check_memory, mem_available_bytes,
    pass_two_budget_bytes,
};
use std::collections::HashMap;
use std::time::Duration;

const REQUIRED: [(&str, &str); 8] = [
    (
        "ENCLAVE_API_URL",
        "https://p.supabase.co/functions/v1/attested-appraisal",
    ),
    (
        "ENCLAVE_RPC_URLS",
        "https://a.example/rpc,https://b.example/rpc",
    ),
    (
        "ENCLAVE_REGISTRY",
        "0x5db410d07931efc7cf1d01545e773992ab1988b2",
    ),
    ("ENCLAVE_CHAIN_ID", "43113"),
    ("ENCLAVE_MEMORY_GB", "4"),
    (
        "ENCLAVE_IPFS_GATEWAYS",
        "https://gateway.example,https://second.example",
    ),
    (
        "ENCLAVE_ARTIFACTS_URL",
        "https://p.supabase.co/storage/v1/object/public/zk-artifacts",
    ),
    (
        "ENCLAVE_ENGINE_SHA256",
        "0x9bec14d49e3a56512cc0e54f7bd0d060841376ab94c301b7df7bfe3bba6a466d",
    ),
];

fn read(extra: &[(&str, &str)], without: &[&str]) -> Result<Config, ConfigError> {
    let mut env: HashMap<String, String> = REQUIRED
        .iter()
        .chain(extra)
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    for name in without {
        env.remove(*name);
    }
    Config::from_lookup(&|name| env.get(name).cloned())
}

/// With the required settings alone, every other setting has its default.
#[test]
fn the_required_settings_alone_give_the_defaults() {
    let config = read(&[], &[]).expect("config");
    assert_eq!(config.sidecar_url, "http://localhost:8080");
    assert_eq!(config.maa_endpoint, "sharedeus.eus.attest.azure.net");
    assert_eq!(config.appraisal_circuit, "tabular_appraisal_r7");
    assert_eq!(config.cache_dir.to_str(), Some("/var/lib/enclave/cache"));
    assert_eq!(config.parallel_fetches, 8);
    assert_eq!(config.engine_deadline, Duration::from_secs(6 * 3600));
    assert_eq!(
        config.ipfs_gateways,
        ["https://gateway.example", "https://second.example"]
    );
    assert_eq!(config.chain_id, 43113);
    assert_eq!(config.memory_gb, 4);
    assert_eq!(
        config.rpc_urls,
        ["https://a.example/rpc", "https://b.example/rpc"]
    );
}

/// Every setting that has no default is named when it is missing.
#[test]
fn each_missing_required_setting_is_named() {
    for (name, _) in REQUIRED {
        assert_eq!(
            read(&[], &[name]),
            Err(ConfigError::Missing(
                REQUIRED.iter().find(|(n, _)| *n == name).expect("name").0
            )),
            "{name}"
        );
    }
}

/// Settings given in the environment replace the defaults.
#[test]
fn given_settings_replace_the_defaults() {
    let config = read(
        &[
            ("ENCLAVE_SIDECAR_URL", "http://127.0.0.1:9000/x"),
            ("ENCLAVE_MAA_ENDPOINT", "sharedweu.weu.attest.azure.net"),
            ("ENCLAVE_APPRAISAL_CIRCUIT", "tabular_appraisal_r8"),
            ("ENCLAVE_CACHE_DIR", "/c"),
            ("ENCLAVE_PARALLEL_FETCHES", "64"),
            ("ENCLAVE_ENGINE_DEADLINE_SECS", "90"),
        ],
        &[],
    )
    .expect("config");
    assert_eq!(config.sidecar_url, "http://127.0.0.1:9000/x");
    assert_eq!(config.maa_endpoint, "sharedweu.weu.attest.azure.net");
    assert_eq!(config.appraisal_circuit, "tabular_appraisal_r8");
    assert_eq!(config.cache_dir.to_str(), Some("/c"));
    assert_eq!(config.parallel_fetches, 64);
    assert_eq!(config.engine_deadline, Duration::from_secs(90));
}

/// A sidecar address may omit the port, and a name may be 64 characters.
#[test]
fn a_sidecar_without_a_port_and_a_longest_name_are_accepted() {
    let long = "a".repeat(64);
    let config = read(
        &[
            ("ENCLAVE_SIDECAR_URL", "http://localhost/attest"),
            ("ENCLAVE_APPRAISAL_CIRCUIT", &long),
        ],
        &[],
    )
    .expect("config");
    assert_eq!(config.sidecar_url, "http://localhost/attest");
    assert_eq!(config.appraisal_circuit, long);
}

/// A value that is not valid for its setting is refused, and the setting is named.
#[test]
fn malformed_values_are_refused() {
    let five_gateways = ["https://g.example"; 5].join(",");
    let nine_urls = ["https://x.example"; 9].join(",");
    let too_long = "a".repeat(65);
    let cases: Vec<(&str, &str)> = vec![
        ("ENCLAVE_API_URL", "http://p.supabase.co/f"),
        ("ENCLAVE_API_URL", "https://"),
        ("ENCLAVE_API_URL", "https://p.co/a b"),
        ("ENCLAVE_API_URL", "ftp://p.co"),
        ("ENCLAVE_RPC_URLS", ""),
        ("ENCLAVE_RPC_URLS", "https://a.example,"),
        ("ENCLAVE_RPC_URLS", "https://a.example,http://b.example"),
        ("ENCLAVE_RPC_URLS", &nine_urls),
        (
            "ENCLAVE_REGISTRY",
            "5db410d07931efc7cf1d01545e773992ab1988b2",
        ),
        ("ENCLAVE_REGISTRY", "0x12"),
        ("ENCLAVE_CHAIN_ID", "0"),
        ("ENCLAVE_MEMORY_GB", "0"),
        ("ENCLAVE_MEMORY_GB", "33"),
        ("ENCLAVE_MEMORY_GB", "4 GB"),
        ("ENCLAVE_MEMORY_GB", "-4"),
        ("ENCLAVE_CHAIN_ID", "-1"),
        ("ENCLAVE_CHAIN_ID", "43113 "),
        ("ENCLAVE_CHAIN_ID", "99999999999999999999999"),
        ("ENCLAVE_IPFS_GATEWAYS", "http://gateway.example"),
        ("ENCLAVE_IPFS_GATEWAYS", "https://a.example,"),
        (
            "ENCLAVE_IPFS_GATEWAYS",
            "https://a.example,http://b.example",
        ),
        ("ENCLAVE_IPFS_GATEWAYS", &five_gateways),
        ("ENCLAVE_ARTIFACTS_URL", "gateway.example"),
        (
            "ENCLAVE_ENGINE_SHA256",
            "9bec14d49e3a56512cc0e54f7bd0d060841376ab94c301b7df7bfe3bba6a466d",
        ),
        ("ENCLAVE_ENGINE_SHA256", "0x12"),
        ("ENCLAVE_SIDECAR_URL", "https://localhost:8080"),
        ("ENCLAVE_SIDECAR_URL", "http://evil.example:8080"),
        ("ENCLAVE_SIDECAR_URL", "http://localhost.evil.example"),
        ("ENCLAVE_SIDECAR_URL", "http://evil:8080"),
        ("ENCLAVE_MAA_ENDPOINT", ""),
        ("ENCLAVE_MAA_ENDPOINT", "a/b"),
        (
            "ENCLAVE_MAA_ENDPOINT",
            "https://sharedeus.eus.attest.azure.net",
        ),
        ("ENCLAVE_APPRAISAL_CIRCUIT", "../x"),
        ("ENCLAVE_APPRAISAL_CIRCUIT", &too_long),
        ("ENCLAVE_PARALLEL_FETCHES", "0"),
        ("ENCLAVE_PARALLEL_FETCHES", "65"),
        ("ENCLAVE_PARALLEL_FETCHES", "many"),
        ("ENCLAVE_ENGINE_DEADLINE_SECS", "0"),
        ("ENCLAVE_ENGINE_DEADLINE_SECS", "1h"),
    ];
    for (name, value) in cases {
        let error = read(&[(name, value)], &[]).expect_err(&format!("{name}={value}"));
        assert_eq!(
            error,
            ConfigError::Invalid(
                REQUIRED
                    .iter()
                    .map(|(n, _)| *n)
                    .chain([
                        "ENCLAVE_SIDECAR_URL",
                        "ENCLAVE_MAA_ENDPOINT",
                        "ENCLAVE_APPRAISAL_CIRCUIT",
                        "ENCLAVE_PARALLEL_FETCHES",
                        "ENCLAVE_ENGINE_DEADLINE_SECS",
                    ])
                    .find(|n| *n == name)
                    .expect("name")
            ),
            "{name}={value}"
        );
    }
}

/// The cgroup must show at least 85% of the configured memory, in gibibytes: a decimal gigabyte container passes, one that
/// the platform keeps much of does not.
#[test]
fn the_cgroup_must_show_most_of_the_configured_memory() {
    let gib: u64 = 1 << 30;
    // A decimal 2, 4 and 16 GB container is 93% of the gibibytes
    for (gb, bytes) in [
        (2u32, 2_000_000_000u64),
        (4, 4_000_000_000),
        (16, 16_000_000_000),
    ] {
        assert_eq!(check_memory(&format!("{bytes}\n"), gb), Ok(()), "{gb} GB");
    }
    assert_eq!(check_memory(&format!("{}", 4 * gib), 4), Ok(()));
    assert_eq!(
        check_memory(&format!("{}", 8 * gib), 4),
        Ok(()),
        "more than configured"
    );
    // The floor is 85% of the gibibytes, exactly
    let floor = 4 * gib / 100 * 85;
    assert_eq!(check_memory(&floor.to_string(), 4), Ok(()));
    assert_eq!(
        check_memory(&(floor - 1).to_string(), 4),
        Err(ConfigError::Memory)
    );
    for bad in ["max\n", "", "x", "-1", "0", "99999999999999999999999"] {
        assert_eq!(check_memory(bad, 4), Err(ConfigError::Memory), "{bad}");
    }
    // A cgroup v1 with no limit shows a value near 2^63, which is no limit
    assert_eq!(
        check_memory("9223372036854771712", 4),
        Err(ConfigError::Memory)
    );
    assert_eq!(
        check_memory(&((1u64 << 62) - 1).to_string(), 4),
        Ok(()),
        "the largest value that is still a limit"
    );
}

/// What Azure Container Instances shows: cgroup v1, whose limit is exactly the configured gibibytes, and no cgroup v2
/// `memory.max`. Either file is used when it is the only one, the v2 file wins when both exist, and neither is an error.
#[test]
fn the_limit_comes_from_cgroup_v2_or_v1_and_a_container_with_neither_is_refused() {
    let gib: u64 = 1 << 30;
    for gb in [2u32, 4, 16] {
        let v1 = format!("{}\n", u64::from(gb) * gib);
        let text = cgroup_limit_text(None, Some(&v1)).expect("v1 limit");
        assert_eq!(check_memory(text, gb), Ok(()), "{gb} GB on cgroup v1");
    }
    assert_eq!(cgroup_limit_text(Some("max\n"), None), Ok("max\n"));
    assert_eq!(cgroup_limit_text(Some("123"), Some("456")), Ok("123"));
    assert_eq!(
        check_memory(
            cgroup_limit_text(Some("max\n"), Some("4294967296")).expect("text"),
            4
        ),
        Err(ConfigError::Memory),
        "a v2 file that says max is not a limit, whatever the v1 file says"
    );
    assert_eq!(cgroup_limit_text(None, None), Err(ConfigError::Memory));
}

/// `MemAvailable` is read in kilobytes from the text of `/proc/meminfo`: the values Azure showed at 2, 4 and 16 GB.
#[test]
fn memory_available_is_read_from_meminfo() {
    let meminfo = "MemTotal:        1879552 kB\nMemFree:         1700000 kB\nMemAvailable:    1705232 kB\nBuffers:               0 kB\n";
    assert_eq!(mem_available_bytes(meminfo), Ok(1_705_232 * 1024));
    for bad in [
        "",
        "MemTotal: 1 kB\n",
        "MemAvailable: x kB\n",
        "MemAvailable: 5\n",
        "MemAvailable: 5 MB\n",
        "MemAvailable: -5 kB\n",
        "MemAvailable: 18446744073709551615 kB\n",
    ] {
        assert_eq!(
            mem_available_bytes(bad),
            Err(ConfigError::Memory),
            "{bad:?}"
        );
    }
}

/// Pass 2 gets half of the memory the container has, at least 256 MiB and at most 1 GiB.
#[test]
fn the_pass_two_budget_is_half_the_memory_between_256_mib_and_1_gib() {
    let mib: u64 = 1 << 20;
    let plenty = u64::MAX;
    assert_eq!(pass_two_budget_bytes(1, plenty), 512 * mib);
    assert_eq!(pass_two_budget_bytes(2, plenty), 1024 * mib);
    assert_eq!(pass_two_budget_bytes(32, plenty), 1024 * mib);
    assert_eq!(pass_two_budget_bytes(1, 100 * mib), 256 * mib);
    assert_eq!(pass_two_budget_bytes(1, 0), 256 * mib);
}

/// What the guest really has is about 90% of the configured size, and the budget follows the smaller of that and the
/// configured size: at 2 GB Azure showed 1705232 kB available.
#[test]
fn the_pass_two_budget_follows_the_available_memory_when_that_is_less_than_configured() {
    let available = 1_705_232u64 * 1024;
    assert_eq!(pass_two_budget_bytes(2, available), available / 2);
    assert_eq!(pass_two_budget_bytes(1, available), 512 << 20);
    assert_eq!(pass_two_budget_bytes(2, 900 << 20), 450 << 20);
    assert_eq!(pass_two_budget_bytes(2, 64 << 30), 1 << 30);
}
