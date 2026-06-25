//! Confirm-to-act queue. Heuristic detections (high RAM, leaks, duplicate/orphan
//! pileups, sustained CPU) and AI-escalated strategies NEVER kill anything on
//! their own — they enqueue a `Proposal` here. The dashboard's Pending tab is
//! where the user approves or dismisses. Approving verifies the target is still
//! the same process, executes the kill, logs it, and removes it from the queue.
//!
//! (User-defined config rules with `action: "kill"/"restart"` are a separate,
//! pre-authorized path handled by `optimize.rs` and are not gated by this.)
use crate::config::state_dir;
use crate::util::now_epoch;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use sysinfo::{Pid, System};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Proposal {
    pub id: String,
    /// Currently always "kill".
    pub kind: String,
    pub pid: u32,
    /// Process start time — disambiguates a reused PID from the original target.
    pub start: u64,
    pub name: String,
    pub mem_mb: u64,
    /// Why this was proposed (the finding title, or the AI suggestion).
    pub reason: String,
    /// "high_ram" | "mem_leak" | "orphans" | "duplicates" | "cpu_sustained" | "ai"
    pub source: String,
    pub ts: u64,
}

fn path() -> PathBuf {
    state_dir().join("pending.json")
}

pub fn load() -> Vec<Proposal> {
    std::fs::read_to_string(path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn store(list: &[Proposal]) {
    if let Ok(t) = serde_json::to_string_pretty(list) {
        let _ = std::fs::write(path(), t);
    }
}

fn key(p: &Proposal) -> String {
    format!("{}:{}:{}", p.kind, p.pid, p.start)
}

/// Merge freshly-proposed actions into the queue. `live` maps each live pid to
/// its start time; a proposal is kept only if that exact (pid, start) is still
/// alive — so a PID reused by a different process drops the stale proposal
/// instead of leaving a misleading entry. New unique proposals are added; the
/// queue length is capped.
pub fn merge_new(fresh: Vec<Proposal>, live: &HashMap<u32, u64>) {
    let alive = |p: &Proposal| live.get(&p.pid) == Some(&p.start);
    let mut cur = load();
    cur.retain(alive);
    let mut seen: HashSet<String> = cur.iter().map(key).collect();
    for p in fresh {
        if alive(&p) && seen.insert(key(&p)) {
            cur.push(p);
        }
    }
    const CAP: usize = 200;
    if cur.len() > CAP {
        cur = cur.split_off(cur.len() - CAP);
    }
    store(&cur);
}

pub fn dismiss(id: &str) {
    let mut cur = load();
    cur.retain(|p| p.id != id);
    store(&cur);
}

/// Dismiss every pending proposal for one process name (case-insensitive).
/// Returns how many were removed. Used by the dashboard's grouped "Dismiss all".
pub fn dismiss_group(name: &str) -> usize {
    let mut cur = load();
    let before = cur.len();
    cur.retain(|p| !p.name.eq_ignore_ascii_case(name));
    let removed = before - cur.len();
    store(&cur);
    removed
}

/// Approve every pending proposal for one process name (case-insensitive) in one
/// shot: re-verify + kill each (a reused PID is never hit), log, and drop the whole
/// group from the queue. Returns a summary like "Killed 11/12 msedgewebview2.exe
/// (~407 MB)." Powers the dashboard's grouped "Approve & kill all".
pub fn approve_group(name: &str) -> Result<String, String> {
    let mut sys = System::new();
    sys.refresh_processes();
    let (mut killed, mut freed, mut total) = (0usize, 0u64, 0usize);
    let mut cur = load();
    cur.retain(|p| {
        if !p.name.eq_ignore_ascii_case(name) {
            return true; // keep proposals for other apps
        }
        total += 1;
        if let Some(pr) = sys.process(Pid::from(p.pid as usize)) {
            if pr.name().eq_ignore_ascii_case(&p.name) && pr.start_time() == p.start && pr.kill() {
                killed += 1;
                freed += p.mem_mb;
            }
        }
        false // resolved (killed, gone, or reused) — remove from the queue
    });
    if total == 0 {
        return Err("No matching proposals.".into());
    }
    store(&cur);
    log(&format!(
        "approved group {name} — killed {killed}/{total} ~{freed}MB"
    ));
    Ok(format!("Killed {killed}/{total} {name} (~{freed} MB)."))
}

pub fn count() -> usize {
    load().len()
}

fn log(msg: &str) {
    use std::io::Write;
    let p = state_dir().join("ram-optimizer.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
    {
        let _ = writeln!(f, "[{}] CONFIRM {}", now_epoch(), msg);
    }
}

/// Execute an approved proposal: re-verify the pid maps to the same process,
/// kill it, log, remove from the queue. Returns a human-readable message.
pub fn approve(id: &str) -> Result<String, String> {
    let prop = load()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or("Proposal not found.")?;

    let mut sys = System::new();
    sys.refresh_processes();
    let result = match sys.process(Pid::from(prop.pid as usize)) {
        Some(pr) if pr.name().eq_ignore_ascii_case(&prop.name) && pr.start_time() == prop.start => {
            Ok(pr.kill())
        }
        Some(_) => {
            Err("PID was reused by a different process — removed without acting.".to_string())
        }
        None => Err("Process already gone — removed.".to_string()),
    };
    dismiss(id);
    match result {
        Ok(true) => {
            log(&format!(
                "approved {} pid {} ({}) ~{}MB [{}]",
                prop.kind, prop.pid, prop.name, prop.mem_mb, prop.source
            ));
            Ok(format!(
                "Killed {} (pid {}, ~{} MB).",
                prop.name, prop.pid, prop.mem_mb
            ))
        }
        Ok(false) => Err(format!(
            "Failed to kill {} (pid {}) — insufficient rights? Try running elevated.",
            prop.name, prop.pid
        )),
        Err(e) => Err(e),
    }
}
