//! The workload that runs inside the attested confidential container.
//!
//! The harness is public so anyone can read what the owner consents to. It claims a job, obtains the dataset key
//! through the decrypt Lit Action, runs the appraisal engine as a sandboxed WebAssembly module over the decrypted
//! bytes, and returns a signed result.

pub mod api;
pub mod attest;
pub mod chain;
pub mod check;
pub mod circom;
pub mod claim;
pub mod config;
pub mod consent;
pub mod engine;
pub mod error_code;
pub mod job;
pub mod keys;
pub mod label;
pub mod lit;
pub mod manifest;
pub mod metrics;
pub mod pipeline;
pub mod prove;
pub mod qap;
pub mod result;
pub mod runtime_data;
pub mod store;
pub mod zkey;
