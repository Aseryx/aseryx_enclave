//! Spike 0.5 probe: runs the vendored aseryx-engine WebAssembly module (the file browsers run) under wasmtime
//! with no JavaScript, supplying the four imports wasm-bindgen declares. Prints the appraisal JSON.
//!
//! Usage: wasm-probe <module.wasm> <data file> <format> <file name> <salt hex or ->

use wasmtime::{Caller, Engine, ExternRef, Instance, Linker, Module, Ref, Result, Rooted, Store, Table, Val, bail, format_err as anyhow};

trait Context<T> {
    fn context(self, message: &str) -> Result<T>;
    fn with_context<F: FnOnce() -> String>(self, message: F) -> Result<T>;
}
impl<T> Context<T> for Option<T> {
    fn context(self, message: &str) -> Result<T> {
        self.ok_or_else(|| anyhow!("{message}"))
    }
    fn with_context<F: FnOnce() -> String>(self, message: F) -> Result<T> {
        self.ok_or_else(|| anyhow!("{}", message()))
    }
}

const GLUE: &str = "./aseryx_engine_wasm_bg.js";
const FEED_SLICE: usize = 1 << 20;

#[derive(Default)]
struct State {
    table: Option<Table>,
}

fn read_string(caller: &mut Caller<'_, State>, ptr: i32, len: i32) -> Result<String> {
    let memory = caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| anyhow!("no memory export"))?;
    let data = memory.data(&caller);
    let (start, end) = (ptr as u32 as usize, ptr as u32 as usize + len as u32 as usize);
    let bytes = data.get(start..end).ok_or_else(|| anyhow!("string out of bounds"))?;
    Ok(String::from_utf8(bytes.to_vec())?)
}

fn link(linker: &mut Linker<State>) -> Result<()> {
    linker.func_wrap(GLUE, "__wbg_Error_30c8987f7c2ed4e2", |mut caller: Caller<'_, State>, ptr: i32, len: i32| {
        let text = read_string(&mut caller, ptr, len)?;
        Ok(Some(ExternRef::new(&mut caller, text)?))
    })?;
    linker.func_wrap(GLUE, "__wbindgen_generic_0000000000000001", |mut caller: Caller<'_, State>, ptr: i32, len: i32| {
        let text = read_string(&mut caller, ptr, len)?;
        Ok(Some(ExternRef::new(&mut caller, text)?))
    })?;
    linker.func_wrap(GLUE, "__wbg___wbindgen_throw_41e9ee4f547fc59a", |mut caller: Caller<'_, State>, ptr: i32, len: i32| -> Result<()> {
        let text = read_string(&mut caller, ptr, len)?;
        bail!("wasm threw: {text}")
    })?;
    linker.func_wrap(GLUE, "__wbindgen_init_externref_table", |mut caller: Caller<'_, State>| -> Result<()> {
        let table = caller.data().table.ok_or_else(|| anyhow!("table not set"))?;
        let offset = table.grow(&mut caller, 4, Ref::Extern(None))?;
        table.set(&mut caller, 0, Ref::Extern(None))?;
        for i in 0..4 {
            table.set(&mut caller, offset + i, Ref::Extern(None))?;
        }
        Ok(())
    })?;
    Ok(())
}

struct Engine2 {
    store: Store<State>,
    instance: Instance,
}

impl Engine2 {
    fn call(&mut self, name: &str, args: &[Val], results: usize) -> Result<Vec<i32>> {
        let func = self.instance.get_func(&mut self.store, name).with_context(|| format!("export {name}"))?;
        let mut out = vec![Val::I32(0); results];
        func.call(&mut self.store, args, &mut out)?;
        Ok(out.iter().map(|v| v.unwrap_i32()).collect())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<i32> {
        let ptr = self.call("__wbindgen_malloc", &[Val::I32(bytes.len() as i32), Val::I32(1)], 1)?[0];
        let memory = self.instance.get_memory(&mut self.store, "memory").context("memory")?;
        memory.write(&mut self.store, ptr as u32 as usize, bytes)?;
        Ok(ptr)
    }

    fn read(&mut self, ptr: i32, len: i32) -> Result<Vec<u8>> {
        let memory = self.instance.get_memory(&mut self.store, "memory").context("memory")?;
        let start = ptr as u32 as usize;
        Ok(memory.data(&self.store)[start..start + len as u32 as usize].to_vec())
    }

    fn take_error(&mut self, index: i32) -> Result<String> {
        let table = self.store.data().table.context("table")?;
        let value = table.get(&mut self.store, index as u64).context("empty error slot")?;
        let extern_ref: Option<&Rooted<ExternRef>> = value.as_extern().flatten();
        let text = match extern_ref {
            Some(e) => match e.data(&self.store)? {
                Some(d) => d.downcast_ref::<String>().cloned().unwrap_or_else(|| "non-string error".to_string()),
                None => "host data missing".to_string(),
            },
            None => "null error".to_string(),
        };
        self.call("__externref_table_dealloc", &[Val::I32(index)], 0)?;
        Ok(text)
    }

    fn string_result(&mut self, name: &str) -> Result<String> {
        let r = self.call(name, &[], 2)?;
        let text = String::from_utf8(self.read(r[0], r[1])?)?;
        self.call("__wbindgen_free", &[Val::I32(r[0]), Val::I32(r[1]), Val::I32(1)], 0)?;
        Ok(text)
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        bail!("usage: wasm-probe <module.wasm> <data file> <format> <file name> <salt hex or ->");
    }
    let engine = Engine::default();
    let module = Module::from_file(&engine, &args[1])?;
    let mut linker = Linker::new(&engine);
    link(&mut linker)?;
    let mut store = Store::new(&engine, State::default());
    let instance = linker.instantiate(&mut store, &module)?;
    let table = instance.get_table(&mut store, "__wbindgen_externrefs").context("externref table")?;
    store.data_mut().table = Some(table);
    let mut e = Engine2 { store, instance };
    e.call("__wbindgen_start", &[], 0)?;

    eprintln!("version {} model {} rules {} hash {}", e.string_result("version")?, e.string_result("model")?, e.string_result("rulesVersion")?, e.string_result("rulesHash")?);

    let data = std::fs::read(&args[2])?;
    let (file, format) = (args[4].as_bytes().to_vec(), args[3].as_bytes().to_vec());
    let salt = if args[5] == "-" { None } else { Some(args[5].as_bytes().to_vec()) };
    let (fp, ft) = (e.write(&file)?, e.write(&format)?);
    let (sp, sl) = match &salt {
        Some(s) => (e.write(s)?, s.len() as i32),
        None => (0, 0),
    };
    let r = e.call(
        "appraisal_new",
        &[Val::I32(fp), Val::I32(file.len() as i32), Val::I32(ft), Val::I32(format.len() as i32), Val::I32(sp), Val::I32(sl)],
        3,
    )?;
    if r[2] != 0 {
        bail!("appraisal_new: {}", e.take_error(r[1])?);
    }
    let handle = r[0];

    let mut passes = 0;
    loop {
        for slice in data.chunks(FEED_SLICE) {
            let p = e.write(slice)?;
            e.call("appraisal_feed", &[Val::I32(handle), Val::I32(p), Val::I32(slice.len() as i32)], 0)?;
        }
        passes += 1;
        let n = e.call("appraisal_nextPass", &[Val::I32(handle)], 3)?;
        if n[2] != 0 {
            bail!("nextPass: {}", e.take_error(n[1])?);
        }
        if n[0] == 0 {
            break;
        }
    }
    let f = e.call("appraisal_finish", &[Val::I32(handle)], 4)?;
    if f[3] != 0 {
        bail!("finish: {}", e.take_error(f[2])?);
    }
    let json = String::from_utf8(e.read(f[0], f[1])?)?;
    e.call("__wbindgen_free", &[Val::I32(f[0]), Val::I32(f[1]), Val::I32(1)], 0)?;
    eprintln!("passes fed: {passes}");
    println!("{json}");
    Ok(())
}
