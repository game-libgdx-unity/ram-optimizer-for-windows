//! Cross-platform process/RAM/CPU snapshot via the native `sysinfo` crate —
//! no PowerShell/`ps` shell-outs.
use crate::util::now_epoch;
use serde::{Deserialize, Serialize};
use sysinfo::{ProcessRefreshKind, System};

#[derive(Serialize, Deserialize, Clone)]
pub struct Proc {
    pub pid: u32,
    #[serde(default)]
    pub ppid: Option<u32>,
    pub name: String,
    #[serde(rename = "memMB")]
    pub mem_mb: u64,
    pub cpu: f64,
    pub start: u64,
    #[serde(default)]
    pub cmd: String,
    /// Full executable path (for `match.pathContains` rules). May be empty for
    /// protected processes when not running elevated.
    #[serde(default)]
    pub exe: String,
    /// Raw argv — used to relaunch a process after a restart-after-kill. Not
    /// persisted (only needed within the pass that collected it).
    #[serde(default, skip_serializing)]
    pub argv: Vec<String>,
    /// Working directory, for an accurate relaunch. Not persisted.
    #[serde(default, skip_serializing)]
    pub cwd: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Snapshot {
    pub epoch: u64,
    #[serde(rename = "totalMB")]
    pub total_mb: u64,
    #[serde(rename = "usedMB")]
    pub used_mb: u64,
    #[serde(rename = "usedPct")]
    pub used_pct: f64,
    pub procs: Vec<Proc>,
}

pub fn collect() -> Snapshot {
    let mut sys = System::new();
    sys.refresh_memory();
    // everything() also pulls the command line + exe path (needed for rule
    // matching); the plain refresh_processes() does not. Two passes around the
    // minimum interval so per-process CPU% is a real delta.
    sys.refresh_processes_specifics(ProcessRefreshKind::everything());
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_processes_specifics(ProcessRefreshKind::everything());

    let total = sys.total_memory();
    let avail = sys.available_memory();
    let used = total.saturating_sub(avail);
    let total_mb = total / 1_048_576;
    let used_mb = used / 1_048_576;
    let used_pct = if total > 0 {
        used as f64 / total as f64 * 100.0
    } else {
        0.0
    };

    let mut procs = Vec::with_capacity(sys.processes().len());
    for (pid, p) in sys.processes() {
        procs.push(Proc {
            pid: pid.as_u32(),
            ppid: p.parent().map(|pp| pp.as_u32()),
            name: p.name().to_string(),
            mem_mb: p.memory() / 1_048_576,
            cpu: p.cpu_usage() as f64,
            start: p.start_time(),
            cmd: p.cmd().join(" "),
            exe: p
                .exe()
                .map(|e| e.to_string_lossy().into_owned())
                .unwrap_or_default(),
            argv: p.cmd().to_vec(),
            cwd: p
                .cwd()
                .map(|c| c.to_string_lossy().into_owned())
                .unwrap_or_default(),
        });
    }

    Snapshot {
        epoch: now_epoch(),
        total_mb,
        used_mb,
        used_pct,
        procs,
    }
}

/// Cheap memory-only reading (no process enumeration): `(total_mb, used_mb, used_pct)`.
/// Used to measure RAM right after the optimizer acts, without a second full scan.
pub fn mem_snapshot() -> (u64, u64, f64) {
    let mut sys = System::new();
    sys.refresh_memory();
    let total = sys.total_memory();
    let used = total.saturating_sub(sys.available_memory());
    let used_pct = if total > 0 {
        used as f64 / total as f64 * 100.0
    } else {
        0.0
    };
    (total / 1_048_576, used / 1_048_576, used_pct)
}
