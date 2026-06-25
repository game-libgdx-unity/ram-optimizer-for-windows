//! A hardcoded floor of operating-system-critical processes that the automatic
//! kill tiers (`optimize::auto_relief` and the reap in `detect::reap_targets`)
//! must NEVER touch — independent of the user-editable `thresholds.ignoreNames`.
//!
//! `ignoreNames` is the user's preference lever: trim it (even to nothing) to let
//! RAM Optimizer reclaim from apps it would otherwise spare, e.g. a browser. This floor
//! is the safety net underneath that lever — killing `svchost.exe`, `lsass.exe`,
//! `WindowServer`, … can instantly crash or log out the machine, so those are
//! protected here in code and an empty ignore-list can never reach them.
//!
//! Cross-platform: covers Windows, macOS, and Linux names so the check is correct
//! wherever the crate runs. Matching is exact (case-insensitive) on the process
//! name, never substring, so it can't accidentally shield an unrelated app.

/// OS-critical process names (lowercase). Killing any of these destabilizes the
/// session or the whole machine, so the auto-kill tiers always skip them.
const CRITICAL: &[&str] = &[
    // ---- Windows kernel / session / security (fatal to kill) ----
    "system idle process",
    "system",
    "registry",
    "memory compression",
    "idle",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "explorer.exe",
    "conhost.exe",
    "ctfmon.exe",
    "sihost.exe",
    "taskhostw.exe",
    // ---- macOS core ----
    "kernel_task",
    "launchd",
    "windowserver",
    "loginwindow",
    "logd",
    "configd",
    // ---- Linux core ----
    "systemd",
    "init",
    "kthreadd",
];

/// Is this an OS-critical process the auto-kill tiers must never target?
pub fn is_critical_system_process(name: &str) -> bool {
    let n = name.trim().to_lowercase();
    CRITICAL.iter().any(|c| *c == n)
}

#[cfg(test)]
mod tests {
    use super::is_critical_system_process;

    #[test]
    fn protects_os_processes_case_insensitively() {
        assert!(is_critical_system_process("svchost.exe"));
        assert!(is_critical_system_process("SvcHost.exe"));
        assert!(is_critical_system_process("lsass.exe"));
        assert!(is_critical_system_process("System Idle Process"));
        assert!(is_critical_system_process("WindowServer"));
        assert!(is_critical_system_process("systemd"));
    }

    #[test]
    fn does_not_protect_regular_apps() {
        assert!(!is_critical_system_process("chrome.exe"));
        assert!(!is_critical_system_process("node.exe"));
        assert!(!is_critical_system_process("java.exe"));
        assert!(!is_critical_system_process("MsMpEng.exe"));
        // Exact match only — never a substring (so "systemic.exe" stays killable).
        assert!(!is_critical_system_process("systemic.exe"));
    }
}
