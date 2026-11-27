//! The appraisal engine, linked as a static library and called through its C ABI.
//!
//! `engine/libaseryx_engine_ffi.a` is the library of an `aseryx-engine` release (`ffi/` of that repository). This crate
//! declares its functions, owns every `unsafe` call and gives the rest of the workspace safe types: [`Appraisal`],
//! [`LabelCheck`] and [`ThresholdCount`] runs, and the engine's functions of text. [`LIBRARY_SHA256`] is the SHA-256 of
//! the library file the crate was linked with, computed when it was built.
//!
//! A run is fed the whole file, [`next_pass`](Appraisal::next_pass) says whether to feed it again, and `finish` returns
//! the result as JSON text. Every result is the text the WebAssembly package returns for the same bytes.

use std::ptr;
use std::slice;

/// The SHA-256 of the engine library this crate was linked with.
pub const LIBRARY_SHA256: [u8; 32] = include!(concat!(env!("OUT_DIR"), "/library_sha256.rs"));

const OK: i32 = 0;
const BAD_ARGUMENT: i32 = 1;
const REFUSED: i32 = 2;
const PANICKED: i32 = 3;

/// Why an engine call did not succeed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The engine refused the input; the text is its message, for example a malformed label.
    #[error("{0}")]
    Refused(String),
    /// The call was malformed: a null pointer or text that is not UTF-8.
    #[error("the engine was called with a bad argument: {0}")]
    BadArgument(String),
    /// The engine panicked.
    #[error("the engine panicked: {0}")]
    Panicked(String),
    /// The engine returned a status this crate does not know.
    #[error("the engine returned status {0}")]
    Status(i32),
}

#[repr(C)]
struct Buffer {
    ptr: *mut u8,
    len: usize,
}

#[repr(C)]
struct RawAppraisal {
    _private: [u8; 0],
}

#[repr(C)]
struct RawLabelCheck {
    _private: [u8; 0],
}

#[repr(C)]
struct RawThresholdCount {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn aseryx_buffer_free(buffer: Buffer);
    fn aseryx_version(out: *mut Buffer) -> i32;
    fn aseryx_family(out: *mut Buffer) -> i32;
    fn aseryx_model(out: *mut Buffer) -> i32;
    fn aseryx_rules_version(out: *mut Buffer) -> i32;
    fn aseryx_rules_hash(out: *mut Buffer) -> i32;
    fn aseryx_threshold_circuit_revision() -> u32;
    fn aseryx_label_hash(label: *const u8, label_len: usize, out: *mut Buffer) -> i32;
    fn aseryx_threshold_witness(
        result: *const u8,
        result_len: usize,
        check_hash: *const u8,
        check_hash_len: usize,
        allowed_failure_permille: u32,
        out: *mut Buffer,
    ) -> i32;
    fn aseryx_appraisal_new(
        file: *const u8,
        file_len: usize,
        format: *const u8,
        format_len: usize,
        salt: *const u8,
        salt_len: usize,
        manifest_id: *const u8,
        manifest_id_len: usize,
        handle: *mut *mut RawAppraisal,
        err: *mut Buffer,
    ) -> i32;
    fn aseryx_appraisal_set_pass_two_budget(
        handle: *mut RawAppraisal,
        bytes: u64,
        err: *mut Buffer,
    ) -> i32;
    fn aseryx_appraisal_feed(handle: *mut RawAppraisal, bytes: *const u8, len: usize) -> i32;
    fn aseryx_appraisal_next_pass(
        handle: *mut RawAppraisal,
        again: *mut i32,
        err: *mut Buffer,
    ) -> i32;
    fn aseryx_appraisal_finish(handle: *mut RawAppraisal, out: *mut Buffer) -> i32;
    fn aseryx_appraisal_free(handle: *mut RawAppraisal);
    fn aseryx_label_check_new(
        label: *const u8,
        label_len: usize,
        handle: *mut *mut RawLabelCheck,
        err: *mut Buffer,
    ) -> i32;
    fn aseryx_label_check_feed(handle: *mut RawLabelCheck, bytes: *const u8, len: usize) -> i32;
    fn aseryx_label_check_next_pass(handle: *mut RawLabelCheck, again: *mut i32) -> i32;
    fn aseryx_label_check_finish(handle: *mut RawLabelCheck, out: *mut Buffer) -> i32;
    fn aseryx_label_check_free(handle: *mut RawLabelCheck);
    fn aseryx_threshold_count_new(
        label: *const u8,
        label_len: usize,
        check: *const u8,
        check_len: usize,
        handle: *mut *mut RawThresholdCount,
        err: *mut Buffer,
    ) -> i32;
    fn aseryx_threshold_count_feed(
        handle: *mut RawThresholdCount,
        bytes: *const u8,
        len: usize,
    ) -> i32;
    fn aseryx_threshold_count_next_pass(handle: *mut RawThresholdCount, again: *mut i32) -> i32;
    fn aseryx_threshold_count_finish(handle: *mut RawThresholdCount, out: *mut Buffer) -> i32;
    fn aseryx_threshold_count_free(handle: *mut RawThresholdCount);
}

fn empty() -> Buffer {
    Buffer {
        ptr: ptr::null_mut(),
        len: 0,
    }
}

/// The text in a buffer, which is released.
fn take(buffer: Buffer) -> String {
    let text = if buffer.ptr.is_null() {
        String::new()
    } else {
        // SAFETY: the library returned `ptr` and `len` as one allocation that nothing else holds.
        let bytes = unsafe { slice::from_raw_parts(buffer.ptr, buffer.len) };
        String::from_utf8_lossy(bytes).into_owned()
    };
    // SAFETY: `buffer` came from the library and is released once, here.
    unsafe { aseryx_buffer_free(buffer) };
    text
}

fn failure(status: i32, message: String) -> Error {
    match status {
        BAD_ARGUMENT => Error::BadArgument(message),
        REFUSED => Error::Refused(message),
        PANICKED => Error::Panicked(message),
        other => Error::Status(other),
    }
}

/// A call that returns text in a buffer.
fn text_call(call: impl FnOnce(*mut Buffer) -> i32) -> Result<String, Error> {
    let mut out = empty();
    let status = call(&mut out);
    let text = take(out);
    if status == OK {
        Ok(text)
    } else {
        Err(failure(status, text))
    }
}

/// A call that reports a failure's message in a buffer and returns nothing else.
fn unit_call(call: impl FnOnce(*mut Buffer) -> i32) -> Result<(), Error> {
    text_call(call).map(|_| ())
}

/// A call with a status and no message.
fn status_call(status: i32) -> Result<(), Error> {
    if status == OK {
        Ok(())
    } else {
        Err(failure(status, String::new()))
    }
}

/// What the engine says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// The engine's crate version.
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

/// What the linked engine says about itself.
///
/// # Errors
///
/// [`Error`] if the engine does not answer.
pub fn info() -> Result<Info, Error> {
    // SAFETY: each getter writes one buffer through the pointer it is given.
    unsafe {
        Ok(Info {
            version: text_call(|o| aseryx_version(o))?,
            family: text_call(|o| aseryx_family(o))?,
            model: text_call(|o| aseryx_model(o))?,
            rules_version: text_call(|o| aseryx_rules_version(o))?,
            rules_hash: text_call(|o| aseryx_rules_hash(o))?,
        })
    }
}

/// The revision of the threshold circuits, part of their names `threshold_r<revision>_c<conditions>`.
#[must_use]
pub fn threshold_circuit_revision() -> u32 {
    // SAFETY: the function takes no arguments and touches no memory of the caller.
    unsafe { aseryx_threshold_circuit_revision() }
}

/// The hash of a data label as the engine computes it, a decimal field element.
///
/// # Errors
///
/// [`Error::Refused`] when the text is not a data label.
pub fn label_hash(label_json: &str) -> Result<String, Error> {
    // SAFETY: the pointer and length describe `label_json`, which outlives the call.
    text_call(|out| unsafe { aseryx_label_hash(label_json.as_ptr(), label_json.len(), out) })
}

/// The threshold circuit's input for one counted check, from the count's JSON result, the check's hash and its allowed
/// failure in permille.
///
/// # Errors
///
/// [`Error::Refused`] when the engine refuses the result or the hash.
pub fn threshold_witness(
    result_json: &str,
    check_hash: &str,
    allowed_failure_permille: u32,
) -> Result<String, Error> {
    // SAFETY: each pointer and length describe a string that outlives the call.
    text_call(|out| unsafe {
        aseryx_threshold_witness(
            result_json.as_ptr(),
            result_json.len(),
            check_hash.as_ptr(),
            check_hash.len(),
            allowed_failure_permille,
            out,
        )
    })
}

fn passes(again: i32) -> bool {
    again == 1
}

/// An appraisal of one file.
pub struct Appraisal {
    handle: *mut RawAppraisal,
}

impl Appraisal {
    /// Starts an appraisal. `format` is the file extension without its dot, `salt` is 64 lower-case hex digits and
    /// `manifest_id` the vault manifest's identifier, each optional.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] when the engine refuses the salt or the identifier.
    pub fn new(
        file: &str,
        format: &str,
        salt: Option<&str>,
        manifest_id: Option<&str>,
    ) -> Result<Self, Error> {
        let (salt, manifest_id) = (salt.unwrap_or(""), manifest_id.unwrap_or(""));
        let mut handle: *mut RawAppraisal = ptr::null_mut();
        // SAFETY: each pointer and length describe a string that outlives the call; `handle` is written once.
        unit_call(|err| unsafe {
            aseryx_appraisal_new(
                file.as_ptr(),
                file.len(),
                format.as_ptr(),
                format.len(),
                salt.as_ptr(),
                salt.len(),
                manifest_id.as_ptr(),
                manifest_id.len(),
                &mut handle,
                err,
            )
        })?;
        Ok(Self { handle })
    }

    /// Sets the memory pass 2 may hold, in bytes (1 MiB to 64 GiB), before pass 1 ends: a larger budget means fewer
    /// readings of the file and the same result.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] for a budget out of range or one set after pass 1.
    pub fn set_pass_two_budget(&mut self, bytes: u64) -> Result<(), Error> {
        // SAFETY: `handle` is a live appraisal that only this value holds.
        unit_call(|err| unsafe { aseryx_appraisal_set_pass_two_budget(self.handle, bytes, err) })
    }

    /// Gives the appraisal the next bytes of the current pass.
    ///
    /// # Errors
    ///
    /// [`Error`] when the engine fails.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        // SAFETY: `handle` is live; the pointer and length describe `bytes`.
        status_call(unsafe { aseryx_appraisal_feed(self.handle, bytes.as_ptr(), bytes.len()) })
    }

    /// Ends the current pass: true when the file must be fed again from the start, false when `finish` is next.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] with the engine's message when the pass cannot end.
    pub fn next_pass(&mut self) -> Result<bool, Error> {
        let mut again = 0;
        // SAFETY: `handle` is live; `again` is written once.
        unit_call(|err| unsafe { aseryx_appraisal_next_pass(self.handle, &mut again, err) })?;
        Ok(passes(again))
    }

    /// The appraisal as JSON once every pass is done.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] with the engine's message when the file cannot be appraised.
    pub fn finish(self) -> Result<String, Error> {
        let handle = self.handle;
        std::mem::forget(self);
        // SAFETY: `handle` is live and consumed by this call, whatever its status.
        text_call(|out| unsafe { aseryx_appraisal_finish(handle, out) })
    }
}

impl Drop for Appraisal {
    fn drop(&mut self) {
        // SAFETY: `handle` is live and was not finished.
        unsafe { aseryx_appraisal_free(self.handle) };
    }
}

/// A check of whether a data label describes one file.
pub struct LabelCheck {
    handle: *mut RawLabelCheck,
}

impl LabelCheck {
    /// Starts a check of the data label given as JSON text.
    ///
    /// # Errors
    ///
    /// [`Error`] when the engine cannot start the check.
    pub fn new(label_json: &str) -> Result<Self, Error> {
        let mut handle: *mut RawLabelCheck = ptr::null_mut();
        // SAFETY: the pointer and length describe `label_json`; `handle` is written once.
        unit_call(|err| unsafe {
            aseryx_label_check_new(label_json.as_ptr(), label_json.len(), &mut handle, err)
        })?;
        Ok(Self { handle })
    }

    /// Gives the check the next bytes of the current pass.
    ///
    /// # Errors
    ///
    /// [`Error`] when the engine fails.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        // SAFETY: `handle` is live; the pointer and length describe `bytes`.
        status_call(unsafe { aseryx_label_check_feed(self.handle, bytes.as_ptr(), bytes.len()) })
    }

    /// Ends the current pass: true when the file must be fed again, false when `finish` is next.
    ///
    /// # Errors
    ///
    /// [`Error`] when the engine fails.
    pub fn next_pass(&mut self) -> Result<bool, Error> {
        let mut again = 0;
        // SAFETY: `handle` is live; `again` is written once.
        status_call(unsafe { aseryx_label_check_next_pass(self.handle, &mut again) })?;
        Ok(passes(again))
    }

    /// The result as JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] with the engine's message when the check fails.
    pub fn finish(self) -> Result<String, Error> {
        let handle = self.handle;
        std::mem::forget(self);
        // SAFETY: `handle` is live and consumed by this call, whatever its status.
        text_call(|out| unsafe { aseryx_label_check_finish(handle, out) })
    }
}

impl Drop for LabelCheck {
    fn drop(&mut self) {
        // SAFETY: `handle` is live and was not finished.
        unsafe { aseryx_label_check_free(self.handle) };
    }
}

/// A count of the rows of one file that meet a threshold check.
pub struct ThresholdCount {
    handle: *mut RawThresholdCount,
}

impl ThresholdCount {
    /// Starts a count of the check given as JSON text on the file the data label given as JSON text describes.
    ///
    /// # Errors
    ///
    /// [`Error`] when the engine cannot start the count.
    pub fn new(label_json: &str, check_json: &str) -> Result<Self, Error> {
        let mut handle: *mut RawThresholdCount = ptr::null_mut();
        // SAFETY: each pointer and length describe a string that outlives the call; `handle` is written once.
        unit_call(|err| unsafe {
            aseryx_threshold_count_new(
                label_json.as_ptr(),
                label_json.len(),
                check_json.as_ptr(),
                check_json.len(),
                &mut handle,
                err,
            )
        })?;
        Ok(Self { handle })
    }

    /// Gives the count the next bytes of the current pass.
    ///
    /// # Errors
    ///
    /// [`Error`] when the engine fails.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        // SAFETY: `handle` is live; the pointer and length describe `bytes`.
        status_call(unsafe {
            aseryx_threshold_count_feed(self.handle, bytes.as_ptr(), bytes.len())
        })
    }

    /// Ends the current pass: true when the file must be fed again (it is read twice), false when `finish` is next.
    ///
    /// # Errors
    ///
    /// [`Error`] when the engine fails.
    pub fn next_pass(&mut self) -> Result<bool, Error> {
        let mut again = 0;
        // SAFETY: `handle` is live; `again` is written once.
        status_call(unsafe { aseryx_threshold_count_next_pass(self.handle, &mut again) })?;
        Ok(passes(again))
    }

    /// The result as JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] with the engine's message when the count fails.
    pub fn finish(self) -> Result<String, Error> {
        let handle = self.handle;
        std::mem::forget(self);
        // SAFETY: `handle` is live and consumed by this call, whatever its status.
        text_call(|out| unsafe { aseryx_threshold_count_finish(handle, out) })
    }
}

impl Drop for ThresholdCount {
    fn drop(&mut self) {
        // SAFETY: `handle` is live and was not finished.
        unsafe { aseryx_threshold_count_free(self.handle) };
    }
}
