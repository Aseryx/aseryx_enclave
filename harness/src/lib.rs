//! The workload that runs inside the attested confidential container.
//!
//! The harness is public so anyone can read what the owner consents to. It claims a job, obtains the dataset key
//! through the decrypt Lit Action, runs the appraisal engine as a sandboxed WebAssembly module over the decrypted
//! bytes, and returns a signed result.

pub mod attest;
pub mod claim;
pub mod consent;
pub mod engine;
pub mod error_code;
pub mod keys;
pub mod runtime_data;
