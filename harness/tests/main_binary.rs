//! The binary refuses to start, before it claims anything, when its settings or surroundings are wrong.

use std::process::Command;

fn run(env: &[(&str, &str)]) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_aseryx-enclave"))
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .expect("runs");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Without settings the binary exits with 2 and names the first missing one.
#[test]
fn without_settings_it_exits_2_and_names_the_missing_one() {
    let (code, stderr) = run(&[]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("ENCLAVE_RPC_URLS is not set"), "{stderr}");
}

/// A malformed setting stops it the same way, and the message carries the setting's name, not its value.
#[test]
fn a_malformed_setting_stops_it_without_echoing_the_value() {
    let (code, stderr) = run(&[
        ("ENCLAVE_RPC_URLS", "https://rpc.example"),
        ("ENCLAVE_MEMORY_GB", "4"),
        ("ENCLAVE_CHAIN_ID", "43113"),
        ("ENCLAVE_API_URL", "http://not-https.example/secretish"),
    ]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("ENCLAVE_API_URL is not valid"), "{stderr}");
    assert!(!stderr.contains("secretish"), "{stderr}");
}
