//! Computing a circuit's witness with the WebAssembly module `circom` generates, under wasmtime.
//!
//! This is the glue `witness_calculator.js` in circom's runtime implements, written for wasmtime so the image carries one
//! WebAssembly runtime. It is adapted from `ark-circom`'s witness calculator (MIT OR Apache-2.0,
//! <https://github.com/arkworks-rs/circom-compat>). The module is public, pinned by its SHA-256, and gets only the
//! memory it declares and logging callbacks; the two callbacks circom calls on an assertion failure trap, so a witness
//! that violates the circuit is never produced.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use std::collections::BTreeMap;
use wasmtime::{
    Engine, Extern, ExternType, Func, Instance, Linker, Memory, Module, Store, TypedFunc, Val,
    ValType,
};

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;
const TRAPPING_CALLBACKS: [&str; 2] = ["error", "exceptionHandler"];

/// Why a witness could not be computed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WitnessError {
    /// The module does not compile, or imports something circom's runtime does not provide.
    #[error("the circuit module was refused: {0}")]
    Module(String),
    /// The module does not have the interface circom generates, or works over another field.
    #[error("the circuit module does not have circom's interface")]
    Interface,
    /// An input does not fit the field or the circuit.
    #[error("an input does not fit the circuit")]
    Input,
    /// The module trapped, for example because the inputs violate an assertion of the circuit.
    #[error("the circuit rejected the inputs: {0}")]
    Trap(String),
}

fn module_error(error: impl std::fmt::Display) -> WitnessError {
    WitnessError::Module(error.to_string().chars().take(120).collect())
}

fn trap(error: impl std::fmt::Display) -> WitnessError {
    WitnessError::Trap(error.to_string().chars().take(120).collect())
}

/// The 64-bit FNV-1a hash of a signal's name, as the high and low 32 bits, the way circom addresses inputs.
fn name_hash(name: &str) -> (u32, u32) {
    let hash = name.bytes().fold(FNV_OFFSET, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(FNV_PRIME)
    });
    ((hash >> 32) as u32, hash as u32)
}

/// A compiled circuit module.
pub struct Circuit {
    engine: Engine,
    module: Module,
}

struct Exports {
    init: TypedFunc<i32, ()>,
    field_len: TypedFunc<(), i32>,
    raw_prime: TypedFunc<(), ()>,
    read: TypedFunc<i32, i32>,
    write: TypedFunc<(i32, i32), ()>,
    set_input: TypedFunc<(i32, i32, i32), ()>,
    input_size: TypedFunc<(), i32>,
    witness_size: TypedFunc<(), i32>,
    witness: TypedFunc<i32, ()>,
}

fn export<P: wasmtime::WasmParams, R: wasmtime::WasmResults>(
    store: &mut Store<()>,
    instance: &Instance,
    name: &str,
) -> Result<TypedFunc<P, R>, WitnessError> {
    instance
        .get_typed_func::<P, R>(&mut *store, name)
        .map_err(|_| WitnessError::Interface)
}

impl Exports {
    fn new(store: &mut Store<()>, instance: &Instance) -> Result<Self, WitnessError> {
        Ok(Self {
            init: export(store, instance, "init")?,
            field_len: export(store, instance, "getFieldNumLen32")?,
            raw_prime: export(store, instance, "getRawPrime")?,
            read: export(store, instance, "readSharedRWMemory")?,
            write: export(store, instance, "writeSharedRWMemory")?,
            set_input: export(store, instance, "setInputSignal")?,
            input_size: export(store, instance, "getInputSize")?,
            witness_size: export(store, instance, "getWitnessSize")?,
            witness: export(store, instance, "getWitness")?,
        })
    }
}

impl Circuit {
    /// Compiles a circuit module and checks that its imports are the ones circom's runtime provides.
    ///
    /// # Errors
    ///
    /// [`WitnessError::Module`] for a module that does not compile or imports anything else.
    pub fn new(wasm: &[u8]) -> Result<Self, WitnessError> {
        let engine = Engine::default();
        let module = Module::new(&engine, wasm).map_err(module_error)?;
        for import in module.imports() {
            let known = match (import.module(), import.ty()) {
                ("env", ExternType::Memory(_)) => import.name() == "memory",
                ("runtime", ExternType::Func(_)) => true,
                _ => false,
            };
            if !known {
                return Err(WitnessError::Module(format!(
                    "unexpected import {}.{}",
                    import.module(),
                    import.name()
                )));
            }
        }
        Ok(Self { engine, module })
    }

    fn instantiate(&self) -> Result<(Store<()>, Instance), WitnessError> {
        let mut store = Store::new(&self.engine, ());
        let mut linker = Linker::new(&self.engine);
        for import in self.module.imports() {
            match import.ty() {
                ExternType::Memory(ty) => {
                    let memory = Memory::new(&mut store, ty).map_err(module_error)?;
                    linker
                        .define(
                            &store,
                            import.module(),
                            import.name(),
                            Extern::Memory(memory),
                        )
                        .map_err(module_error)?;
                }
                ExternType::Func(ty) => {
                    let name = import.name().to_owned();
                    let fails = TRAPPING_CALLBACKS.contains(&import.name());
                    let func = Func::new(&mut store, ty, move |_caller, _params, results| {
                        if fails {
                            wasmtime::bail!("the circuit called {name}");
                        }
                        for slot in results.iter_mut() {
                            *slot = match slot.ty(&_caller) {
                                Ok(ValType::I64) => Val::I64(0),
                                _ => Val::I32(0),
                            };
                        }
                        Ok(())
                    });
                    linker
                        .define(&store, import.module(), import.name(), Extern::Func(func))
                        .map_err(module_error)?;
                }
                _ => return Err(WitnessError::Interface),
            }
        }
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(module_error)?;
        Ok((store, instance))
    }

    /// The witness for named inputs (a scalar is a one-element list, an array its elements in order), as field elements in circuit order (the constant one first, then the public
    /// signals, then the private ones).
    ///
    /// # Errors
    ///
    /// [`WitnessError::Interface`] if the module works over another field, [`WitnessError::Input`] for an input that does
    /// not fit or for inputs that do not number the circuit's, and [`WitnessError::Trap`] if the circuit rejects the inputs.
    pub fn witness(
        &self,
        inputs: &BTreeMap<String, Vec<BigUint>>,
    ) -> Result<Vec<Fr>, WitnessError> {
        let (mut store, instance) = self.instantiate()?;
        let ex = Exports::new(&mut store, &instance)?;
        ex.init.call(&mut store, 0).map_err(trap)?;
        let words = usize::try_from(ex.field_len.call(&mut store, ()).map_err(trap)?)
            .map_err(|_| WitnessError::Interface)?;
        ex.raw_prime.call(&mut store, ()).map_err(trap)?;
        let prime = read_number(&ex, &mut store, words)?;
        if prime != BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be()) {
            return Err(WitnessError::Interface);
        }
        for (name, values) in inputs {
            let (high, low) = name_hash(name);
            for (position, value) in values.iter().enumerate() {
                if value.bits() > 32 * words as u64 {
                    return Err(WitnessError::Input);
                }
                let mut digits = value.to_u32_digits();
                digits.resize(words, 0);
                for (j, digit) in digits.iter().enumerate() {
                    ex.write
                        .call(
                            &mut store,
                            (
                                i32::try_from(j).map_err(|_| WitnessError::Input)?,
                                *digit as i32,
                            ),
                        )
                        .map_err(trap)?;
                }
                ex.set_input
                    .call(
                        &mut store,
                        (
                            high as i32,
                            low as i32,
                            i32::try_from(position).map_err(|_| WitnessError::Input)?,
                        ),
                    )
                    .map_err(trap)?;
            }
        }
        let given: usize = inputs.values().map(Vec::len).sum();
        if usize::try_from(ex.input_size.call(&mut store, ()).map_err(trap)?).ok() != Some(given) {
            return Err(WitnessError::Input);
        }
        let size = ex.witness_size.call(&mut store, ()).map_err(trap)?;
        (0..size)
            .map(|i| {
                ex.witness.call(&mut store, i).map_err(trap)?;
                let value = read_number(&ex, &mut store, words)?;
                Ok(Fr::from_be_bytes_mod_order(&value.to_bytes_be()))
            })
            .collect()
    }
}

/// The number in the module's shared memory: `words` little-endian 32-bit digits.
fn read_number(ex: &Exports, store: &mut Store<()>, words: usize) -> Result<BigUint, WitnessError> {
    let mut digits = Vec::with_capacity(words);
    for j in 0..words {
        let word = ex
            .read
            .call(
                &mut *store,
                i32::try_from(j).map_err(|_| WitnessError::Interface)?,
            )
            .map_err(trap)?;
        digits.push(word as u32);
    }
    Ok(BigUint::new(digits))
}
