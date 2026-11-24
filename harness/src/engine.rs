//! The appraisal engine: the `appraisal_core_wasm_bg.wasm` module that browsers run, hosted in wasmtime.
//!
//! The module is pinned by its SHA-256 and may import only the four functions wasm-bindgen declares, so it has no way
//! to reach a clock, a file or a network. The harness hands it decrypted bytes and reads back JSON. Every run has its own
//! instance, a memory cap and a wall-clock deadline.

use crate::consent::Bytes32;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;
use wasmtime::{
    Caller, Config, ExternRef, Instance, Linker, Module, Ref, ResourceLimiter, Rooted, Store,
    Table, Trap, Val,
};

const GLUE: &str = "./appraisal_core_wasm_bg.js";
const IMPORTS: [&str; 4] = [
    "__wbg_Error_30c8987f7c2ed4e2",
    "__wbg___wbindgen_throw_41e9ee4f547fc59a",
    "__wbindgen_generic_0000000000000001",
    "__wbindgen_init_externref_table",
];
const FEED_SLICE_BYTES: usize = 1 << 20;
const TICK: Duration = Duration::from_millis(50);

/// Why the engine could not run.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The module's SHA-256 is not the pinned one.
    #[error("the engine module is not the pinned one: {found}")]
    NotPinned {
        /// The SHA-256 of the module that was given.
        found: Bytes32,
    },
    /// The module could not be compiled or declares an import outside the allowed four.
    #[error("the engine module was refused: {0}")]
    Load(String),
    /// The module could not be instantiated or called.
    #[error("the engine failed: {0}")]
    Host(String),
    /// The run used more memory than its limit allows.
    #[error("the engine ran out of memory")]
    Memory,
    /// The run took longer than its deadline.
    #[error("the engine ran past its deadline")]
    Deadline,
    /// The module reported an error of its own, for example a malformed label.
    #[error("the engine reported: {0}")]
    Module(String),
}

/// The limits of one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The wall-clock time a run may take, from its creation, including the time between calls.
    pub deadline: Duration,
    /// The most linear memory the module may hold, in bytes.
    pub max_memory_bytes: usize,
}

/// What the module says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    /// The package version.
    pub version: String,
    /// The formula family.
    pub family: String,
    /// The model.
    pub model: String,
    /// The rules version.
    pub rules_version: String,
    /// The frozen rules hash, as a decimal field element.
    pub rules_hash: String,
}

/// Which engine a run drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Appraisal,
    LabelCheck,
    ThresholdCount,
}

impl Kind {
    fn export(self, op: &str) -> String {
        let prefix = match self {
            Self::Appraisal => "appraisal",
            Self::LabelCheck => "labelcheck",
            Self::ThresholdCount => "thresholdcount",
        };
        format!("{prefix}_{op}")
    }
}

/// Refuses memory growth past the cap and remembers that it did, so the resulting trap is reported as a memory error.
struct MemoryCap {
    max_bytes: usize,
    denied: bool,
}

impl ResourceLimiter for MemoryCap {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let allowed = desired <= self.max_bytes;
        self.denied |= !allowed;
        Ok(allowed)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(true)
    }
}

struct State {
    table: Option<Table>,
    cap: MemoryCap,
}

fn host_error(error: impl std::fmt::Display) -> EngineError {
    EngineError::Host(error.to_string())
}

fn classify(error: &wasmtime::Error, memory_denied: bool) -> EngineError {
    match error.downcast_ref::<Trap>() {
        Some(Trap::Interrupt) => EngineError::Deadline,
        _ if memory_denied => EngineError::Memory,
        _ => EngineError::Host(error.to_string()),
    }
}

fn read_string(caller: &mut Caller<'_, State>, ptr: i32, len: i32) -> wasmtime::Result<String> {
    let memory = caller
        .get_export("memory")
        .and_then(wasmtime::Extern::into_memory)
        .ok_or_else(|| wasmtime::format_err!("no memory export"))?;
    let start = ptr as u32 as usize;
    let end = start + len as u32 as usize;
    let bytes = memory
        .data(&caller)
        .get(start..end)
        .ok_or_else(|| wasmtime::format_err!("string out of bounds"))?;
    Ok(String::from_utf8(bytes.to_vec())?)
}

fn link(linker: &mut Linker<State>) -> wasmtime::Result<()> {
    linker.func_wrap(
        GLUE,
        IMPORTS[0],
        |mut caller: Caller<'_, State>, ptr: i32, len: i32| {
            let text = read_string(&mut caller, ptr, len)?;
            Ok(Some(ExternRef::new(&mut caller, text)?))
        },
    )?;
    linker.func_wrap(
        GLUE,
        IMPORTS[2],
        |mut caller: Caller<'_, State>, ptr: i32, len: i32| {
            let text = read_string(&mut caller, ptr, len)?;
            Ok(Some(ExternRef::new(&mut caller, text)?))
        },
    )?;
    linker.func_wrap(
        GLUE,
        IMPORTS[1],
        |mut caller: Caller<'_, State>, ptr: i32, len: i32| -> wasmtime::Result<()> {
            let text = read_string(&mut caller, ptr, len)?;
            wasmtime::bail!("the module threw: {text}")
        },
    )?;
    linker.func_wrap(
        GLUE,
        IMPORTS[3],
        |mut caller: Caller<'_, State>| -> wasmtime::Result<()> {
            let table = caller
                .data()
                .table
                .ok_or_else(|| wasmtime::format_err!("the externref table is not set"))?;
            let offset = table.grow(&mut caller, 4, Ref::Extern(None))?;
            table.set(&mut caller, 0, Ref::Extern(None))?;
            for slot in 0..4 {
                table.set(&mut caller, offset + slot, Ref::Extern(None))?;
            }
            Ok(())
        },
    )?;
    Ok(())
}

/// A compiled engine module. Each run it hands out has its own instance.
pub struct EngineModule {
    engine: wasmtime::Engine,
    module: Module,
    limits: Limits,
    stop: Arc<AtomicBool>,
    ticker: Option<JoinHandle<()>>,
}

impl EngineModule {
    /// Compiles the module after checking its SHA-256 against the pin and its imports against the allowed four.
    ///
    /// # Errors
    ///
    /// [`EngineError::NotPinned`] for another module, [`EngineError::Load`] for one that does not compile or imports
    /// anything else.
    pub fn load(bytes: &[u8], pinned: Bytes32, limits: Limits) -> Result<Self, EngineError> {
        let found = Bytes32(Sha256::digest(bytes).into());
        if found != pinned {
            return Err(EngineError::NotPinned { found });
        }
        let mut config = Config::new();
        config.epoch_interruption(true);
        let engine =
            wasmtime::Engine::new(&config).map_err(|e| EngineError::Load(e.to_string()))?;
        let module = Module::new(&engine, bytes).map_err(|e| EngineError::Load(e.to_string()))?;
        for import in module.imports() {
            if import.module() != GLUE || !IMPORTS.contains(&import.name()) {
                return Err(EngineError::Load(format!(
                    "unexpected import {}.{}",
                    import.module(),
                    import.name()
                )));
            }
        }
        let stop = Arc::new(AtomicBool::new(false));
        let ticker = {
            let (engine, stop) = (engine.clone(), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(TICK);
                    engine.increment_epoch();
                }
            })
        };
        Ok(Self {
            engine,
            module,
            limits,
            stop,
            ticker: Some(ticker),
        })
    }

    fn host(&self) -> Result<Host, EngineError> {
        let mut linker = Linker::new(&self.engine);
        link(&mut linker).map_err(host_error)?;
        let state = State {
            table: None,
            cap: MemoryCap {
                max_bytes: self.limits.max_memory_bytes,
                denied: false,
            },
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.cap);
        let ticks = self
            .limits
            .deadline
            .as_millis()
            .div_ceil(TICK.as_millis())
            .max(1);
        store.set_epoch_deadline(u64::try_from(ticks).unwrap_or(u64::MAX));
        let instance = match linker.instantiate(&mut store, &self.module) {
            Ok(instance) => instance,
            Err(error) => return Err(classify(&error, store.data().cap.denied)),
        };
        let table = instance
            .get_table(&mut store, "__wbindgen_externrefs")
            .ok_or_else(|| host_error("no externref table"))?;
        store.data_mut().table = Some(table);
        let mut host = Host { store, instance };
        host.call("__wbindgen_start", &[], 0)?;
        Ok(host)
    }

    /// What the module says about itself.
    ///
    /// # Errors
    ///
    /// [`EngineError::Host`] if the module cannot be instantiated.
    pub fn info(&self) -> Result<ModuleInfo, EngineError> {
        let mut host = self.host()?;
        Ok(ModuleInfo {
            version: host.string_result("version")?,
            family: host.string_result("family")?,
            model: host.string_result("model")?,
            rules_version: host.string_result("rulesVersion")?,
            rules_hash: host.string_result("rulesHash")?,
        })
    }

    /// Starts an appraisal of one file.
    ///
    /// `format` is the file extension without its dot, `salt` is 64 lower-case hex digits or none, and `manifest_id`
    /// is the vault manifest's identifier.
    ///
    /// # Errors
    ///
    /// [`EngineError::Module`] if the engine refuses an argument.
    pub fn appraisal(
        &self,
        file: &str,
        format: &str,
        salt: Option<&str>,
        manifest_id: Option<&str>,
    ) -> Result<Run, EngineError> {
        let mut host = self.host()?;
        let (file_ptr, format_ptr) = (host.write(file.as_bytes())?, host.write(format.as_bytes())?);
        let (salt_ptr, salt_len) = match salt {
            Some(text) => (host.write(text.as_bytes())?, text.len()),
            None => (0, 0),
        };
        let result = host.call(
            "appraisal_new",
            &[
                Val::I32(file_ptr),
                Val::I32(len(file)),
                Val::I32(format_ptr),
                Val::I32(len(format)),
                Val::I32(salt_ptr),
                Val::I32(i32::try_from(salt_len).map_err(host_error)?),
            ],
            3,
        )?;
        if result[2] != 0 {
            return Err(EngineError::Module(host.take_error(result[1])?));
        }
        if let Some(id) = manifest_id {
            let ptr = host.write(id.as_bytes())?;
            let set = host.call(
                "appraisal_setManifestId",
                &[Val::I32(result[0]), Val::I32(ptr), Val::I32(len(id))],
                2,
            )?;
            if set[1] != 0 {
                return Err(EngineError::Module(host.take_error(set[0])?));
            }
        }
        Ok(Run {
            host,
            handle: result[0],
            kind: Kind::Appraisal,
        })
    }

    /// Starts a check of a data label against one file.
    ///
    /// # Errors
    ///
    /// [`EngineError::Host`] if the module cannot be instantiated.
    pub fn label_check(&self, label_json: &str) -> Result<Run, EngineError> {
        let mut host = self.host()?;
        let ptr = host.write(label_json.as_bytes())?;
        let handle = host.call(
            "labelcheck_new",
            &[Val::I32(ptr), Val::I32(len(label_json))],
            1,
        )?[0];
        Ok(Run {
            host,
            handle,
            kind: Kind::LabelCheck,
        })
    }

    /// Starts a threshold count of one file.
    ///
    /// # Errors
    ///
    /// [`EngineError::Host`] if the module cannot be instantiated.
    pub fn threshold_count(&self, label_json: &str, check_json: &str) -> Result<Run, EngineError> {
        let mut host = self.host()?;
        let (label_ptr, check_ptr) = (
            host.write(label_json.as_bytes())?,
            host.write(check_json.as_bytes())?,
        );
        let handle = host.call(
            "thresholdcount_new",
            &[
                Val::I32(label_ptr),
                Val::I32(len(label_json)),
                Val::I32(check_ptr),
                Val::I32(len(check_json)),
            ],
            1,
        )?[0];
        Ok(Run {
            host,
            handle,
            kind: Kind::ThresholdCount,
        })
    }
}

impl Drop for EngineModule {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(ticker) = self.ticker.take() {
            let _ = ticker.join();
        }
    }
}

fn len(text: &str) -> i32 {
    i32::try_from(text.len()).unwrap_or(i32::MAX)
}

/// One run of an engine over one file: feed every pass, then finish.
pub struct Run {
    host: Host,
    handle: i32,
    kind: Kind,
}

impl Run {
    /// Gives the engine the next bytes of the current pass.
    ///
    /// # Errors
    ///
    /// [`EngineError::Memory`] or [`EngineError::Deadline`] when a limit is hit, [`EngineError::Host`] otherwise.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), EngineError> {
        let export = self.kind.export("feed");
        for slice in bytes.chunks(FEED_SLICE_BYTES) {
            let ptr = self.host.write(slice)?;
            self.host.call(
                &export,
                &[
                    Val::I32(self.handle),
                    Val::I32(ptr),
                    Val::I32(i32::try_from(slice.len()).map_err(host_error)?),
                ],
                0,
            )?;
        }
        Ok(())
    }

    /// Ends the current pass. True means the file must be fed again from the start; false means `finish` is next.
    ///
    /// # Errors
    ///
    /// [`EngineError::Module`] if the engine reports an error, otherwise as for [`Run::feed`].
    pub fn next_pass(&mut self) -> Result<bool, EngineError> {
        let export = self.kind.export("nextPass");
        match self.kind {
            Kind::Appraisal => {
                let r = self.host.call(&export, &[Val::I32(self.handle)], 3)?;
                if r[2] != 0 {
                    return Err(EngineError::Module(self.host.take_error(r[1])?));
                }
                Ok(r[0] != 0)
            }
            Kind::LabelCheck | Kind::ThresholdCount => {
                Ok(self.host.call(&export, &[Val::I32(self.handle)], 1)?[0] != 0)
            }
        }
    }

    /// Ends the run and returns the engine's JSON result.
    ///
    /// # Errors
    ///
    /// [`EngineError::Module`] if the engine reports an error, otherwise as for [`Run::feed`].
    pub fn finish(mut self) -> Result<String, EngineError> {
        let export = self.kind.export("finish");
        let r = self.host.call(&export, &[Val::I32(self.handle)], 4)?;
        if r[3] != 0 {
            return Err(EngineError::Module(self.host.take_error(r[2])?));
        }
        let text = String::from_utf8(self.host.read(r[0], r[1])?).map_err(host_error)?;
        self.host.call(
            "__wbindgen_free",
            &[Val::I32(r[0]), Val::I32(r[1]), Val::I32(1)],
            0,
        )?;
        Ok(text)
    }
}

struct Host {
    store: Store<State>,
    instance: Instance,
}

impl Host {
    fn call(&mut self, name: &str, args: &[Val], results: usize) -> Result<Vec<i32>, EngineError> {
        let func = self
            .instance
            .get_func(&mut self.store, name)
            .ok_or_else(|| host_error(format!("no export {name}")))?;
        let mut out = vec![Val::I32(0); results];
        if let Err(error) = func.call(&mut self.store, args, &mut out) {
            return Err(classify(&error, self.store.data().cap.denied));
        }
        Ok(out.iter().map(Val::unwrap_i32).collect())
    }

    fn memory(&mut self) -> Result<wasmtime::Memory, EngineError> {
        self.instance
            .get_memory(&mut self.store, "memory")
            .ok_or_else(|| host_error("no memory export"))
    }

    fn write(&mut self, bytes: &[u8]) -> Result<i32, EngineError> {
        let size = i32::try_from(bytes.len()).map_err(host_error)?;
        let ptr = self.call("__wbindgen_malloc", &[Val::I32(size), Val::I32(1)], 1)?[0];
        let memory = self.memory()?;
        memory
            .write(&mut self.store, ptr as u32 as usize, bytes)
            .map_err(host_error)?;
        Ok(ptr)
    }

    fn read(&mut self, ptr: i32, length: i32) -> Result<Vec<u8>, EngineError> {
        let memory = self.memory()?;
        let start = ptr as u32 as usize;
        memory
            .data(&self.store)
            .get(start..start + length as u32 as usize)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| host_error("read out of bounds"))
    }

    fn take_error(&mut self, index: i32) -> Result<String, EngineError> {
        let table = self
            .store
            .data()
            .table
            .ok_or_else(|| host_error("no externref table"))?;
        let value = table
            .get(&mut self.store, u64::from(index as u32))
            .ok_or_else(|| host_error("empty error slot"))?;
        let text = match value.as_extern().flatten() {
            Some(slot) => {
                let slot: &Rooted<ExternRef> = slot;
                match slot.data(&self.store).map_err(host_error)? {
                    Some(data) => data
                        .downcast_ref::<String>()
                        .cloned()
                        .unwrap_or_else(|| "an error that is not text".to_owned()),
                    None => "an error with no data".to_owned(),
                }
            }
            None => "an empty error".to_owned(),
        };
        self.call("__externref_table_dealloc", &[Val::I32(index)], 0)?;
        Ok(text)
    }

    fn string_result(&mut self, name: &str) -> Result<String, EngineError> {
        let r = self.call(name, &[], 2)?;
        let text = String::from_utf8(self.read(r[0], r[1])?).map_err(host_error)?;
        self.call(
            "__wbindgen_free",
            &[Val::I32(r[0]), Val::I32(r[1]), Val::I32(1)],
            0,
        )?;
        Ok(text)
    }
}
