//! Small shared helpers: epoch clock + windowless child-process spawning.
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A `Command` that, on Windows, spawns with no console window (CREATE_NO_WINDOW)
/// so scheduled/background runs never flash a black box.
#[cfg(windows)]
pub fn hidden_command(program: &str) -> Command {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut c = Command::new(program);
    c.creation_flags(CREATE_NO_WINDOW);
    c
}

#[cfg(not(windows))]
pub fn hidden_command(program: &str) -> Command {
    Command::new(program)
}
