//! Global log buffer shared between the server and GUI console.
//!
//! All server output that previously went to `eprintln!` is routed through
//! [`log()`] which writes to both stderr and an in-memory ring buffer.  The
//! GUI console drains the buffer each frame via [`drain()`].

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

const MAX_LINES: usize = 2000;

static LOG_BUFFER: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

/// Initialise the global log buffer.  Safe to call more than once.
pub fn init() {
    LOG_BUFFER.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_LINES)));
}

/// Log a message to stderr and append it to the shared buffer.
pub fn log(msg: String) {
    eprintln!("{}", msg);
    if let Some(buf) = LOG_BUFFER.get()
        && let Ok(mut buf) = buf.lock()
    {
        buf.push_back(msg);
        while buf.len() > MAX_LINES {
            buf.pop_front();
        }
    }
}

/// Drain all buffered log lines (used by the GUI console each frame).
pub fn drain() -> Vec<String> {
    if let Some(buf) = LOG_BUFFER.get()
        && let Ok(mut buf) = buf.lock()
    {
        return buf.drain(..).collect();
    }
    Vec::new()
}

/// Convenience macro that replaces `eprintln!`.
macro_rules! glog {
    () => { $crate::logger::log(String::new()) };
    ($($arg:tt)*) => { $crate::logger::log(format!($($arg)*)) };
}
pub(crate) use glog;
