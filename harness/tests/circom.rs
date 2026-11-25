//! The circuit module loader against hand-written modules: the interface and field checks, the callbacks that trap, and
//! the imports that are refused. The modules are WebAssembly text with the exports circom generates.

use aseryx_enclave_harness::circom::{Circuit, WitnessError};
use num_bigint::BigUint;
use std::collections::BTreeMap;

/// A module over the BN254 scalar field whose `setInputSignal` is `on_input`.
fn module(field_words: u32, first_prime_byte: &str, on_input: &str) -> String {
    format!(
        r#"(module
  (import "env" "memory" (memory 1))
  (import "runtime" "error" (func $error (param i32 i32 i32 i32 i32 i32)))
  (data (i32.const 0) "\{first_prime_byte}\00\00\f0\93\f5\e1\43\91\70\b9\79\48\e8\33\28\5d\58\81\81\b6\45\50\b8\29\a0\31\e1\72\4e\64\30")
  (func (export "init") (param i32))
  (func (export "getFieldNumLen32") (result i32) (i32.const {field_words}))
  (func (export "getRawPrime"))
  (func (export "readSharedRWMemory") (param i32) (result i32) (i32.load (i32.mul (local.get 0) (i32.const 4))))
  (func (export "writeSharedRWMemory") (param i32 i32))
  (func (export "setInputSignal") (param i32 i32 i32) {on_input})
  (func (export "getInputSize") (result i32) (i32.const 1))
  (func (export "getWitnessSize") (result i32) (i32.const 0))
  (func (export "getWitness") (param i32)))"#
    )
}

const QUIET: &str = "nop";
const FAILS: &str = "(call $error (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))";

fn inputs() -> BTreeMap<String, Vec<BigUint>> {
    BTreeMap::from([("x".to_owned(), vec![BigUint::from(1u8)])])
}

fn run(text: &str) -> Result<Vec<ark_bn254::Fr>, WitnessError> {
    Circuit::new(text.as_bytes())
        .expect("compiles")
        .witness(&inputs())
}

/// A module with circom's interface over the BN254 field gives a witness.
#[test]
fn a_module_with_circoms_interface_over_the_field_runs() {
    assert_eq!(run(&module(8, "01", QUIET)), Ok(vec![]));
}

/// A module whose numbers are narrower than the field is refused.
#[test]
fn a_module_with_narrow_numbers_is_refused() {
    assert_eq!(run(&module(4, "01", QUIET)), Err(WitnessError::Interface));
}

/// A module over another prime field is refused.
#[test]
fn a_module_over_another_field_is_refused() {
    assert_eq!(run(&module(8, "02", QUIET)), Err(WitnessError::Interface));
}

/// A circuit that calls the error callback traps instead of giving a witness.
#[test]
fn a_circuit_that_calls_the_error_callback_traps() {
    assert!(matches!(
        run(&module(8, "01", FAILS)),
        Err(WitnessError::Trap(_))
    ));
}

/// A module that imports anything but the declared memory and the runtime callbacks is refused.
#[test]
fn a_module_with_other_imports_is_refused() {
    for import in [
        r#"(import "env" "clock" (func))"#,
        r#"(import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))"#,
        r#"(import "env" "other" (memory 1))"#,
    ] {
        let text = format!("(module {import})");
        assert!(
            matches!(Circuit::new(text.as_bytes()), Err(WitnessError::Module(_))),
            "{import}"
        );
    }
    assert!(matches!(
        Circuit::new(b"not a module"),
        Err(WitnessError::Module(_))
    ));
}

/// A module without circom's exports is refused.
#[test]
fn a_module_without_circoms_exports_is_refused() {
    let text = r#"(module (import "env" "memory" (memory 1)))"#;
    assert_eq!(
        Circuit::new(text.as_bytes())
            .expect("compiles")
            .witness(&inputs()),
        Err(WitnessError::Interface)
    );
}

/// An input wider than the field's words is refused before it reaches the circuit.
#[test]
fn an_input_wider_than_the_field_is_refused() {
    let circuit = Circuit::new(module(8, "01", QUIET).as_bytes()).expect("compiles");
    let wide = BTreeMap::from([("x".to_owned(), vec![BigUint::from(1u8) << 256usize])]);
    assert_eq!(circuit.witness(&wide), Err(WitnessError::Input));
}
