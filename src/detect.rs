//! Anomaly detection over the current snapshot (+ the previous one, for CPU/RAM
//! trends). Detection is **generic** — it works on ANY process on the system,
//! never special-casing Claude / shells / CLIs. It flags:
//!   - overall system-RAM pressure,
//!   - per-process high RAM,
//!   - duplicate pileups (many instances of one name),
//!   - orphan pileups (many instances whose parent has died),
//!   - memory leaks (a process whose RAM keeps climbing),
//!   - sustained / sharply-rising CPU,
//!   - the Windows antimalware service eating resources (→ virus advice),
//!   - plus user-defined `action: "alert"` rules.
//!
//! `recognized == false` marks a finding as an AI-escalation candidate.
//! `pids` lists the concrete processes a confirm-to-act proposal may target
//! (empty == nothing to propose, e.g. system-wide or the antimalware service).
use crate::collect::{Proc, Snapshot};
use crate::config::Config;
use crate::rules;
use crate::windefend::is_antimalware;
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
pub struct Finding {
    pub kind: String,
    pub severity: u8,
    pub title: String,
    pub detail: String,
    pub suggestion: String,
    pub recognized: bool,
    /// Concrete kill targets for a confirm-to-act proposal (newest spared).
    pub pids: Vec<u32>,
}

fn short_cmd(c: &str) -> String {
    if c.trim().is_empty() {
        String::new()
    } else {
        format!(" cmd: {}", c.chars().take(120).collect::<String>())
    }
}

/// All but the most-recently-started instance (spare newest) of a group.
fn spare_newest(mut members: Vec<(u32, u64)>) -> Vec<u32> {
    if members.len() <= 1 {
        return vec![];
    }
    members.sort_by_key(|(_, start)| *start);
    members.pop(); // drop newest
    members.into_iter().map(|(pid, _)| pid).collect()
}

/// PIDs to reap for duplicate / orphan / spam pileups of `count`+ instances of one
/// name (newest spared). Skips the ignore-list, the antimalware service, this
/// process, and pid 0. Used by the optimizer's reap tier with a tier-dependent
/// `count` (lower when RAM is critical), independent of the alert thresholds.
pub fn reap_targets(snap: &Snapshot, cfg: &Config, count: usize) -> Vec<u32> {
    let count = count.max(2); // need ≥2 to spare the newest and still reap one
    let ignore: HashSet<String> = cfg
        .thresholds
        .ignore_names
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    // Names the reap tier must never touch (e.g. browsers / Electron apps whose
    // many same-named processes are normal, not a leaked pileup). The relief tier
    // is unaffected — these stay reclaimable under critical RAM.
    let no_reap: HashSet<String> = cfg
        .optimize
        .no_reap_names
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    // Claude's live process tree is the priority to keep alive — never reap it.
    // (Reap spares only the *newest* of a pileup, so it would kill Claude's main
    // process and the guard's "any alive" check would still see the spared helper
    // and not relaunch. Protecting the whole tree is what actually keeps it up.)
    let protect = crate::guard::protected_pids(snap, cfg);
    let self_pid = std::process::id();
    let live: HashSet<u32> = snap.procs.iter().map(|p| p.pid).collect();
    let mut order: Vec<String> = Vec::new();
    let mut members: HashMap<String, Vec<(u32, u64)>> = HashMap::new();
    let mut orphans: HashMap<String, Vec<(u32, u64)>> = HashMap::new();
    for p in &snap.procs {
        let lname = p.name.to_lowercase();
        if p.pid == 0 || p.pid == self_pid || ignore.contains(&lname) || no_reap.contains(&lname) {
            continue;
        }
        if crate::windefend::is_antimalware(&p.name)
            || crate::critical::is_critical_system_process(&p.name)
            || protect.contains(&p.pid)
        {
            continue;
        }
        if !members.contains_key(&p.name) {
            order.push(p.name.clone());
        }
        members
            .entry(p.name.clone())
            .or_default()
            .push((p.pid, p.start));
        if matches!(p.ppid, Some(pp) if pp != 0 && !live.contains(&pp)) {
            orphans
                .entry(p.name.clone())
                .or_default()
                .push((p.pid, p.start));
        }
    }
    let mut out = Vec::new();
    for name in &order {
        if orphans.get(name).map(|o| o.len()).unwrap_or(0) >= count {
            out.extend(spare_newest(orphans[name].clone()));
        } else if members[name].len() >= count {
            out.extend(spare_newest(members[name].clone()));
        }
    }
    out
}

pub fn analyze(snap: &Snapshot, prev: Option<&Snapshot>, cfg: &Config) -> Vec<Finding> {
    let t = &cfg.thresholds;
    let ignore: HashSet<String> = t.ignore_names.iter().map(|s| s.to_lowercase()).collect();
    let live: HashSet<u32> = snap.procs.iter().map(|p| p.pid).collect();
    let mut out: Vec<Finding> = Vec::new();

    // Overall system RAM pressure.
    if snap.used_pct >= t.system_ram_pct_alert {
        out.push(Finding {
            kind: "system_ram".into(),
            severity: 3,
            title: format!("System RAM at {:.0}%", snap.used_pct),
            detail: format!("{} / {} MB used.", snap.used_mb, snap.total_mb),
            suggestion: "Close unused apps / heavy tabs; confirm any pending cleanup actions."
                .into(),
            recognized: true,
            pids: vec![],
        });
    }

    // Per-process high RAM (any app). Only a process eating a big *share* of RAM
    // (>= singleProcRamPct) becomes a kill proposal; merely-large is alert-only.
    for p in &snap.procs {
        if ignore.contains(&p.name.to_lowercase()) {
            continue;
        }
        let pct = if snap.total_mb > 0 {
            p.mem_mb as f64 / snap.total_mb as f64 * 100.0
        } else {
            0.0
        };
        if p.mem_mb >= t.high_ram_mb || pct >= t.single_proc_ram_pct {
            let hog = pct >= t.single_proc_ram_pct;
            out.push(Finding {
                kind: "high_ram".into(),
                severity: if hog { 3 } else { 2 },
                title: format!("{} using {} MB", p.name, p.mem_mb),
                detail: format!(
                    "pid {} ({:.0}% of total RAM){}",
                    p.pid,
                    pct,
                    short_cmd(&p.cmd)
                ),
                suggestion: "If unexpected, inspect/close it; if runaway, restart it.".into(),
                recognized: false,
                pids: if hog { vec![p.pid] } else { vec![] },
            });
        }
    }

    // Group same-named, non-ignored processes once: used for duplicate AND orphan
    // pileups. Tracks instance count, total MB, and (pid,start) members; plus the
    // subset whose parent is no longer alive (orphans).
    let mut order: Vec<String> = Vec::new();
    let mut count: HashMap<String, usize> = HashMap::new();
    let mut mem: HashMap<String, u64> = HashMap::new();
    let mut members: HashMap<String, Vec<(u32, u64)>> = HashMap::new();
    let mut orphans: HashMap<String, Vec<(u32, u64)>> = HashMap::new();
    for p in &snap.procs {
        if ignore.contains(&p.name.to_lowercase()) {
            continue;
        }
        if !count.contains_key(&p.name) {
            order.push(p.name.clone());
        }
        *count.entry(p.name.clone()).or_insert(0) += 1;
        *mem.entry(p.name.clone()).or_insert(0) += p.mem_mb;
        members
            .entry(p.name.clone())
            .or_default()
            .push((p.pid, p.start));
        let parent_dead = matches!(p.ppid, Some(pp) if pp != 0 && !live.contains(&pp));
        if parent_dead {
            orphans
                .entry(p.name.clone())
                .or_default()
                .push((p.pid, p.start));
        }
    }
    for name in &order {
        let c = count[name];
        let m = mem[name];
        // Orphan pileup (parent died) — likely leaked/abandoned helpers.
        if let Some(orph) = orphans.get(name) {
            if orph.len() >= t.orphan_count {
                out.push(Finding {
                    kind: "orphans".into(),
                    severity: 2,
                    title: format!("{}× orphaned {} ({} MB total)", orph.len(), name, m),
                    detail: format!(
                        "{} instances of {} have no live parent — abandoned/leaked helpers.",
                        orph.len(),
                        name
                    ),
                    suggestion: "Reap the orphans (newest spared) to reclaim their RAM.".into(),
                    recognized: false,
                    pids: spare_newest(orph.clone()),
                });
                continue; // don't also report the same name as a plain duplicate
            }
        }
        // Duplicate pileup (regardless of parent).
        if c >= t.dup_count {
            out.push(Finding {
                kind: "duplicates".into(),
                severity: 2,
                title: format!("{}× {} ({} MB total)", c, name, m),
                detail: format!("{} instances of {} — possible leak/orphan pileup.", c, name),
                suggestion: "If these are stray helpers, reap the extras (newest spared).".into(),
                recognized: false,
                pids: spare_newest(members[name].clone()),
            });
        }
    }

    // Trends that need the previous snapshot: CPU + memory growth (leak), for any app.
    if let Some(prev) = prev {
        let prev_by_pid: HashMap<u32, &Proc> = prev.procs.iter().map(|p| (p.pid, p)).collect();
        for p in &snap.procs {
            if ignore.contains(&p.name.to_lowercase()) || p.pid == 0 {
                continue;
            }
            let was = prev_by_pid.get(&p.pid).filter(|q| q.name == p.name);

            // Memory leak: RAM climbing run-over-run on an already-sizeable process.
            if let Some(q) = was {
                let floor = (t.high_ram_mb / 3).max(300);
                let grew = p.mem_mb.saturating_sub(q.mem_mb); // never underflows on a drop
                if p.mem_mb >= floor && grew >= t.mem_rise_mb.max(1) {
                    out.push(Finding {
                        kind: "mem_leak".into(),
                        severity: 3,
                        title: format!(
                            "{} memory climbing ({} → {} MB)",
                            p.name, q.mem_mb, p.mem_mb
                        ),
                        detail: format!(
                            "pid {} grew {} MB since last run — possible leak.{}",
                            p.pid,
                            grew,
                            short_cmd(&p.cmd)
                        ),
                        suggestion: "If it keeps growing, restart it to reclaim the leaked RAM."
                            .into(),
                        recognized: false,
                        pids: vec![p.pid],
                    });
                }
            }

            // CPU: sustained-high or sharply-rising.
            if p.cpu < t.high_cpu_pct {
                continue;
            }
            if let Some(q) = was {
                if q.cpu >= t.high_cpu_pct {
                    out.push(Finding {
                        kind: "cpu_sustained".into(),
                        severity: 3,
                        title: format!("{} sustained {:.0}% CPU", p.name, p.cpu),
                        detail: format!(
                            "pid {} high across two runs (was {:.0}%).{}",
                            p.pid,
                            q.cpu,
                            short_cmd(&p.cmd)
                        ),
                        suggestion:
                            "A genuinely stuck/busy process — inspect; consider restarting.".into(),
                        recognized: false,
                        pids: vec![p.pid],
                    });
                } else if p.cpu - q.cpu >= t.cpu_rise_pct {
                    out.push(Finding {
                        kind: "cpu_rising".into(),
                        severity: 2,
                        title: format!("{} CPU rising ({:.0}% → {:.0}%)", p.name, q.cpu, p.cpu),
                        detail: format!("pid {}.{}", p.pid, short_cmd(&p.cmd)),
                        suggestion: "Watch it; if it keeps climbing it may be a runaway loop."
                            .into(),
                        recognized: false,
                        pids: vec![], // just watch — don't propose killing on a single rise
                    });
                }
            }
        }
    }

    // Windows antimalware service eating resources → virus advice (never killed).
    // Checked outside the ignore filter, since MsMpEng is normally ignored.
    for p in &snap.procs {
        if !is_antimalware(&p.name) {
            continue;
        }
        let sustained = prev
            .and_then(|pv| pv.procs.iter().find(|q| q.pid == p.pid))
            .map(|q| q.cpu >= t.high_cpu_pct)
            .unwrap_or(false);
        let hot = (p.cpu >= t.high_cpu_pct && sustained) || p.mem_mb >= t.high_ram_mb * 2;
        if hot {
            // When the user has opted into auto-taming, explain what the optimizer
            // will do under RAM pressure instead of the "never kill it" advice.
            let suggestion = if cfg.optimize.pause_antimalware_when_idle {
                "Brief spikes during scans are normal. You enabled \
                 optimize.pauseAntimalwareWhenIdle: if system RAM is also high and Defender \
                 reports NO active threats, RAM Optimizer will stop the Defender service to reclaim \
                 resources (needs Tamper Protection off + elevation to succeed). If threats ARE \
                 present it leaves AV running and you should run a full scan."
                    .to_string()
            } else {
                "Brief spikes during scans are normal. If it STAYS high: run a full \
                 scan (Windows Security ▸ Virus & threat protection), then a Microsoft \
                 Defender Offline scan; update definitions; check Task Manager for unfamiliar \
                 processes. Persistently maxed antimalware can mean malware churning files. \
                 Do NOT kill this security service."
                    .to_string()
            };
            out.push(Finding {
                kind: "antimalware".into(),
                severity: 2,
                title: format!(
                    "Antimalware service heavy ({} MB, {:.0}% CPU)",
                    p.mem_mb, p.cpu
                ),
                detail: format!(
                    "Microsoft Defender (MsMpEng, pid {}) is using a lot of resources.",
                    p.pid
                ),
                suggestion,
                recognized: true,
                pids: vec![],
            });
        }
    }

    // User rules with action == "alert".
    for rule in &cfg.rules {
        if !rule.action.eq_ignore_ascii_case("alert") {
            continue;
        }
        let hits = rules::targets(rule, snap);
        if hits.is_empty() {
            continue;
        }
        let mb = rules::total_mb(&hits);
        out.push(Finding {
            kind: format!("rule:{}", rule.name),
            severity: 2,
            title: format!(
                "Rule '{}' matched {} process(es), {} MB",
                rule.name,
                hits.len(),
                mb
            ),
            detail: hits
                .iter()
                .take(3)
                .map(|p| format!("{} (pid {}, {} MB)", p.name, p.pid, p.mem_mb))
                .collect::<Vec<_>>()
                .join("; "),
            suggestion: "Defined by your config rule.".into(),
            recognized: true,
            pids: vec![],
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::reap_targets;
    use crate::collect::{Proc, Snapshot};
    use crate::config::Config;

    fn proc(pid: u32, name: &str) -> Proc {
        Proc {
            pid,
            ppid: None,
            name: name.into(),
            mem_mb: 100,
            cpu: 0.0,
            start: pid as u64,
            cmd: String::new(),
            exe: String::new(),
            argv: Vec::new(),
            cwd: String::new(),
        }
    }

    fn snap(procs: Vec<Proc>) -> Snapshot {
        Snapshot {
            epoch: 0,
            total_mb: 16000,
            used_mb: 8000,
            used_pct: 50.0,
            procs,
        }
    }

    #[test]
    fn reap_skips_no_reap_names_but_still_reaps_others() {
        let mut procs = Vec::new();
        (1..=6).for_each(|pid| procs.push(proc(pid, "chrome.exe"))); // multi-process app
        (11..=16).for_each(|pid| procs.push(proc(pid, "worker.exe"))); // real leaked pileup
        let s = snap(procs);

        let mut c = Config::default();
        c.thresholds.ignore_names = vec![]; // isolate the no-reap behavior
        c.optimize.no_reap_names = vec!["Chrome.exe".into()]; // case-insensitive

        let targets = reap_targets(&s, &c, 5);
        let reaped: Vec<&str> = s
            .procs
            .iter()
            .filter(|p| targets.contains(&p.pid))
            .map(|p| p.name.as_str())
            .collect();
        // Chrome is protected; the worker pileup is reaped (6 → spare newest → 5).
        assert!(reaped.iter().all(|n| *n == "worker.exe"));
        assert_eq!(targets.len(), 5);

        // Without the exclusion, chrome WOULD be reaped — proving no_reap is the cause.
        c.optimize.no_reap_names = vec![];
        let targets2 = reap_targets(&s, &c, 5);
        assert!(s
            .procs
            .iter()
            .any(|p| p.name == "chrome.exe" && targets2.contains(&p.pid)));
    }

    #[test]
    fn reap_never_touches_claude_tree() {
        let mut procs = Vec::new();
        (1..=6).for_each(|pid| procs.push(proc(pid, "claude.exe"))); // Claude pileup
        (11..=16).for_each(|pid| procs.push(proc(pid, "worker.exe"))); // real leaked pileup
        let s = snap(procs);

        // Defaults have guardClaude=true + claudeMarkers=["claude"], so Claude is
        // protected; clear ignoreNames so nothing else shields the worker pileup.
        let mut c = Config::default();
        c.thresholds.ignore_names = vec![];

        let targets = reap_targets(&s, &c, 5);
        let reaped: Vec<&str> = s
            .procs
            .iter()
            .filter(|p| targets.contains(&p.pid))
            .map(|p| p.name.as_str())
            .collect();
        assert!(!reaped.is_empty()); // workers still reaped
        assert!(reaped.iter().all(|n| *n == "worker.exe")); // but never Claude
    }
}
