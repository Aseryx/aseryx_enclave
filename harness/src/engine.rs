//! The appraisal engine: the `aseryx-engine` library linked into the workload, called through `aseryx-engine-native`.
//!
//! The library is pinned by its SHA-256: the settings carry the hash the container is told to run, and the harness
//! starts only when it equals the hash of the library it was built with. The engine reads and writes nothing but the
//! bytes it is given, so it has no way to reach a clock, a file or a network.
//!
//! Every run has a deadline, counted from its creation and checked before each slice of bytes is fed. A call into the
//! engine cannot be interrupted, so a watchdog thread ends the process when a run is still open a grace period
//! ([`Limits::hard_grace`]) after its deadline; the orchestrator then ends the job as timed out, as it does for any workload that posts no result.

use crate::consent::Bytes32;
use aseryx_engine_native as native;
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const FEED_SLICE_BYTES: usize = 1 << 20;
const WATCH_INTERVAL: Duration = Duration::from_secs(1);
/// The exit status of a process the watchdog ended: the job failed and no result was posted.
const WATCHDOG_EXIT: i32 = 1;

/// Why the engine could not run.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The SHA-256 of the linked library is not the pinned one.
    #[error("the engine library is not the pinned one: {found}")]
    NotPinned {
        /// The SHA-256 of the library this build is linked with.
        found: Bytes32,
    },
    /// The engine could not be called.
    #[error("the engine failed: {0}")]
    Host(String),
    /// The run took longer than its deadline.
    #[error("the engine ran past its deadline")]
    Deadline,
    /// The engine reported an error of its own, for example a malformed label.
    #[error("the engine reported: {0}")]
    Module(String),
}

impl From<native::Error> for EngineError {
    fn from(error: native::Error) -> Self {
        match error {
            native::Error::Refused(message) => Self::Module(message),
            other => Self::Host(other.to_string()),
        }
    }
}

/// The limits of one engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The wall-clock time a run may take, from its creation, including the time between calls.
    pub deadline: Duration,
    /// How long past its deadline a run may stay open before the watchdog ends the process: a call into the engine
    /// cannot be interrupted, so this bounds a call that does not return.
    pub hard_grace: Duration,
    /// The memory pass 2 of an appraisal may hold, in bytes. The file is read once more for each slice of the row keys
    /// that does not fit, and every result is the same for any budget.
    pub pass_two_budget_bytes: u64,
}

/// What the engine says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineInfo {
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

struct Open {
    next: u64,
    deadlines: BTreeMap<u64, Instant>,
    stopped: bool,
}

/// Ends the process when a run stays open past its deadline and a grace period.
struct Watchdog {
    state: Arc<(Mutex<Open>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}

fn locked(state: &Mutex<Open>) -> MutexGuard<'_, Open> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Watchdog {
    fn start() -> Self {
        let state = Arc::new((
            Mutex::new(Open {
                next: 0,
                deadlines: BTreeMap::new(),
                stopped: false,
            }),
            Condvar::new(),
        ));
        let watched = Arc::clone(&state);
        let thread = std::thread::spawn(move || {
            let (open, wake) = &*watched;
            let mut guard = locked(open);
            while !guard.stopped {
                if overdue(&guard.deadlines, Instant::now()) {
                    eprintln!(
                        "the engine is past its deadline and cannot be interrupted: ending the process"
                    );
                    std::process::exit(WATCHDOG_EXIT);
                }
                guard = wake
                    .wait_timeout(guard, WATCH_INTERVAL)
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0;
            }
        });
        Self {
            state,
            thread: Some(thread),
        }
    }

    fn open(&self, hard_deadline: Instant) -> u64 {
        let mut guard = locked(&self.state.0);
        guard.next += 1;
        let id = guard.next;
        guard.deadlines.insert(id, hard_deadline);
        id
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        locked(&self.state.0).stopped = true;
        self.state.1.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Whether any open run is past its hard deadline at `now`.
fn overdue(deadlines: &BTreeMap<u64, Instant>, now: Instant) -> bool {
    deadlines.values().any(|hard| now > *hard)
}

/// The engine the workload runs: the linked library and the limits its runs obey.
pub struct NativeEngine {
    limits: Limits,
    watchdog: Watchdog,
}

impl NativeEngine {
    /// The SHA-256 of the engine library this build is linked with.
    #[must_use]
    pub fn library_sha256() -> Bytes32 {
        Bytes32(native::LIBRARY_SHA256)
    }

    /// Starts the engine after checking the pinned SHA-256 against the library this build is linked with.
    ///
    /// # Errors
    ///
    /// [`EngineError::NotPinned`] when the pin is not the linked library's hash.
    pub fn new(pinned: Bytes32, limits: Limits) -> Result<Self, EngineError> {
        let found = Self::library_sha256();
        if found != pinned {
            return Err(EngineError::NotPinned { found });
        }
        Ok(Self {
            limits,
            watchdog: Watchdog::start(),
        })
    }

    fn run(&self, inner: Inner) -> Run {
        let began = Instant::now();
        let id = self
            .watchdog
            .open(began + self.limits.deadline + self.limits.hard_grace);
        Run {
            inner,
            began,
            deadline: self.limits.deadline,
            watch: Watch {
                state: Arc::clone(&self.watchdog.state),
                id,
            },
        }
    }

    /// What the engine says about itself.
    ///
    /// # Errors
    ///
    /// [`EngineError::Host`] if the engine does not answer.
    pub fn info(&self) -> Result<EngineInfo, EngineError> {
        let info = native::info()?;
        Ok(EngineInfo {
            version: info.version,
            family: info.family,
            model: info.model,
            rules_version: info.rules_version,
            rules_hash: info.rules_hash,
        })
    }

    /// Starts an appraisal of one file, with the engine's pass 2 budget set from the limits.
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
        let mut appraisal = native::Appraisal::new(file, format, salt, manifest_id)?;
        appraisal.set_pass_two_budget(self.limits.pass_two_budget_bytes)?;
        Ok(self.run(Inner::Appraisal(appraisal)))
    }

    /// The revision of the threshold circuits this engine builds, which names them `threshold_r<revision>_c<conditions>`.
    #[must_use]
    pub fn threshold_circuit_revision(&self) -> u32 {
        native::threshold_circuit_revision()
    }

    /// The hash of a label, as the engine computes it: a decimal field element.
    ///
    /// # Errors
    ///
    /// [`EngineError::Module`] if the text is not a label.
    pub fn label_hash(&self, label_json: &str) -> Result<String, EngineError> {
        Ok(native::label_hash(label_json)?)
    }

    /// The threshold circuit's input for one counted check, as the engine builds it from the count's JSON result, the
    /// check's hash and its allowed failure in permille.
    ///
    /// # Errors
    ///
    /// [`EngineError::Module`] if the engine refuses the result or the hash.
    pub fn threshold_witness(
        &self,
        result_json: &str,
        check_hash: &str,
        allowed_failure_permille: u32,
    ) -> Result<String, EngineError> {
        Ok(native::threshold_witness(
            result_json,
            check_hash,
            allowed_failure_permille,
        )?)
    }

    /// Starts a check of a data label against one file.
    ///
    /// # Errors
    ///
    /// [`EngineError::Host`] if the engine cannot start the check.
    pub fn label_check(&self, label_json: &str) -> Result<Run, EngineError> {
        Ok(self.run(Inner::LabelCheck(native::LabelCheck::new(label_json)?)))
    }

    /// Starts a threshold count of one file.
    ///
    /// # Errors
    ///
    /// [`EngineError::Host`] if the engine cannot start the count.
    pub fn threshold_count(&self, label_json: &str, check_json: &str) -> Result<Run, EngineError> {
        Ok(self.run(Inner::ThresholdCount(native::ThresholdCount::new(
            label_json, check_json,
        )?)))
    }
}

enum Inner {
    Appraisal(native::Appraisal),
    LabelCheck(native::LabelCheck),
    ThresholdCount(native::ThresholdCount),
}

/// Takes a run off the watchdog's list when the run ends or is dropped.
struct Watch {
    state: Arc<(Mutex<Open>, Condvar)>,
    id: u64,
}

impl Drop for Watch {
    fn drop(&mut self) {
        locked(&self.state.0).deadlines.remove(&self.id);
    }
}

/// One run of an engine over one file: feed every pass, then finish.
pub struct Run {
    inner: Inner,
    began: Instant,
    deadline: Duration,
    #[allow(
        dead_code,
        reason = "dropping it takes the run off the watchdog's list"
    )]
    watch: Watch,
}

impl Run {
    fn in_time(&self) -> Result<(), EngineError> {
        if self.began.elapsed() > self.deadline {
            return Err(EngineError::Deadline);
        }
        Ok(())
    }

    /// Gives the engine the next bytes of the current pass.
    ///
    /// # Errors
    ///
    /// [`EngineError::Deadline`] when the run is past its deadline, [`EngineError::Host`] otherwise.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), EngineError> {
        for slice in bytes.chunks(FEED_SLICE_BYTES) {
            self.in_time()?;
            match &mut self.inner {
                Inner::Appraisal(run) => run.feed(slice),
                Inner::LabelCheck(run) => run.feed(slice),
                Inner::ThresholdCount(run) => run.feed(slice),
            }?;
        }
        Ok(())
    }

    /// Ends the current pass. True means the file must be fed again from the start; false means `finish` is next.
    ///
    /// # Errors
    ///
    /// [`EngineError::Module`] if the engine reports an error, otherwise as for [`Run::feed`].
    pub fn next_pass(&mut self) -> Result<bool, EngineError> {
        self.in_time()?;
        Ok(match &mut self.inner {
            Inner::Appraisal(run) => run.next_pass()?,
            Inner::LabelCheck(run) => run.next_pass()?,
            Inner::ThresholdCount(run) => run.next_pass()?,
        })
    }

    /// Ends the run and returns the engine's JSON result.
    ///
    /// # Errors
    ///
    /// [`EngineError::Module`] if the engine reports an error, otherwise as for [`Run::feed`].
    pub fn finish(self) -> Result<String, EngineError> {
        self.in_time()?;
        Ok(match self.inner {
            Inner::Appraisal(run) => run.finish()?,
            Inner::LabelCheck(run) => run.finish()?,
            Inner::ThresholdCount(run) => run.finish()?,
        })
    }
}
