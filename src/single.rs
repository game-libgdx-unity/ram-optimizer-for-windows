//! Single-instance guard + a "surface the window" signal.
//!
//! Two problems this solves on Windows:
//!   1. Two launches → two tray icons (each process makes its own). `acquire`
//!      lets only the first UI instance proceed; later ones bail.
//!   2. A second launch (double-click while one already runs hidden) — or any
//!      signaller — can ask the running instance to show its window via a named
//!      auto-reset event the running instance waits on.
//!
//! No-ops on non-Windows (the guard always "succeeds"; `wait_show` just paces the
//! caller's loop) — single-instance there can be added later if needed.

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::sync::OnceLock;

    type Handle = *mut c_void;

    extern "system" {
        fn CreateMutexA(attr: *const c_void, owner: i32, name: *const u8) -> Handle;
        fn CreateEventA(attr: *const c_void, manual: i32, initial: i32, name: *const u8) -> Handle;
        fn OpenEventA(access: u32, inherit: i32, name: *const u8) -> Handle;
        fn SetEvent(h: Handle) -> i32;
        fn WaitForSingleObject(h: Handle, ms: u32) -> u32;
        fn GetLastError() -> u32;
    }
    const ERROR_ALREADY_EXISTS: u32 = 183;
    const EVENT_MODIFY_STATE: u32 = 0x0002;
    const WAIT_OBJECT_0: u32 = 0;

    const MUTEX_NAME: &[u8] = b"Local\\RamOptimizerUiSingleton\0";
    const EVENT_NAME: &[u8] = b"Local\\RamOptimizerShowWindow\0";

    // Held for the process lifetime (handles intentionally never closed).
    static MUTEX: OnceLock<usize> = OnceLock::new();
    static EVENT: OnceLock<usize> = OnceLock::new();

    fn show_event() -> Handle {
        let h = EVENT.get_or_init(|| unsafe {
            // Auto-reset, initially non-signalled.
            CreateEventA(std::ptr::null(), 0, 0, EVENT_NAME.as_ptr()) as usize
        });
        *h as Handle
    }

    /// True if this is the first UI instance; false if another already holds the
    /// lock (caller should bail). Also ensures the show-event exists.
    pub fn acquire() -> bool {
        unsafe {
            let h = CreateMutexA(std::ptr::null(), 1, MUTEX_NAME.as_ptr());
            if h.is_null() {
                return true; // can't guard — don't block startup
            }
            let first = GetLastError() != ERROR_ALREADY_EXISTS;
            let _ = MUTEX.set(h as usize);
            let _ = show_event();
            first
        }
    }

    /// Ask the running instance to surface its window (used by a 2nd launch).
    pub fn signal_show() {
        unsafe {
            let h = OpenEventA(EVENT_MODIFY_STATE, 0, EVENT_NAME.as_ptr());
            if !h.is_null() {
                SetEvent(h);
            }
        }
    }

    /// Block up to `ms` for a show request; true if one arrived (auto-resets).
    pub fn wait_show(ms: u32) -> bool {
        unsafe { WaitForSingleObject(show_event(), ms) == WAIT_OBJECT_0 }
    }
}

#[cfg(windows)]
pub use imp::{acquire, signal_show, wait_show};

#[cfg(not(windows))]
pub fn acquire() -> bool {
    true
}
#[cfg(not(windows))]
pub fn signal_show() {}
#[cfg(not(windows))]
pub fn wait_show(ms: u32) -> bool {
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
    false
}
