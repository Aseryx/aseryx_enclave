//! Links the vendored engine library and records its SHA-256, so the crate can say which library it was built with.

use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

const LIBRARY: &str = "libaseryx_engine_ffi.a";
const NAME: &str = "aseryx_engine_ffi";

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let dir = manifest.join("..").join("engine");
    let library = dir.join(LIBRARY);
    println!("cargo:rerun-if-changed={}", library.display());
    println!("cargo:rerun-if-changed=build.rs");

    let bytes = fs::read(&library).unwrap_or_else(|error| {
        panic!(
            "the engine library {} is missing: {error}",
            library.display()
        )
    });
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let mut list = String::new();
    for byte in digest {
        write!(list, "0x{byte:02x}, ").expect("write to a string");
    }
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("library_sha256.rs");
    fs::write(&out, format!("[{list}]")).expect("write the library hash");

    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=static={NAME}");
}
