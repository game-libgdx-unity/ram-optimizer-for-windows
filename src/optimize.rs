//! Optimizer: runs the `kill` / `restart` actions of user rules. `alert` rules are
//! handled in detection. Disabled entirely when `optimize.enabled` is false.
//! Every action is logged to ~/.ram-optimizer/ram-optimizer.log and returned for a toast.
use crate::collect::{Proc, Snapshot};
use crate::config::{state_dir, Config};
use crate::rules;
use crate::util::{hidden_command, now_epoch};
use crate::windefend::{self, ThreatStatus};
use std::collections::HashSet;
use sysinfo::{Pid, System};

#[derive(Default)]
pub struct OptResult {
    pub actions: Vec<String>,
    /// Approx MB freed by the kill/restart actions this run.
    pub reclaimed_mb: u64,
}

fn log(msg: &str) {
    use std::io::Write;
    let p = state_dir().join("ram-optimizer.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
    {
        let _ = writeln!(f, "[{}] OPT {}", now_epoch(), msg);
    }
}

/// Kill the matched processes, but only after re-verifying each PID still maps to
/// the same process (name + start time) it did at snapshot time — so a PID reused
/// between collection and now is never killed by mistake. Returns the count killed.
fn kill_verified(targets: &[&crate::collect::Proc]) -> usize {
    if targets.is_empty() {
        return 0;
    }
    let mut sys = System::new();
    sys.refresh_processes();
    let mut n = 0;
    for t in targets {
        if let Some(p) = sys.process(Pid::from(t.pid as usize)) {
            if p.name().eq_ignore_ascii_case(&t.name) && p.start_time() == t.start && p.kill() {
                n += 1;
            }
        }
    }
    n
}

fn spawn_detached(argv: &[String]) -> bool {
    if argv.is_empty() {
        return false;
    }
    let mut cmd = hidden_command(&argv[0]);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    cmd.spawn().is_ok()
}

pub fn run(snap: &Snapshot, cfg: &Config, meta: &mut crate::state::Meta) -> OptResult {
    if !cfg.optimize.enabled {
        return OptResult::default();
    }

    let mut actions = Vec::new();
    let mut reclaimed_mb = 0u64;

    // Blocklist: kill any "blocked" app on sight, every pass, regardless of RAM —
    // a soft block for apps the user never wants running. Runs before everything.
    let (block_actions, block_mb) = run_blocklist(snap, cfg);
    reclaimed_mb += block_mb;
    actions.extend(block_actions);

    for rule in &cfg.rules {
        let action = rule.action.to_lowercase();
        if action != "kill" && action != "restart" {
            continue; // "alert" handled in detection
        }
        let hits = rules::targets(rule, snap);
        if hits.is_empty() {
            continue;
        }
        let mb = rules::total_mb(&hits);
        let n = kill_verified(&hits);
        if n == 0 {
            continue;
        }
        reclaimed_mb += mb;

        if action == "restart" && !rule.restart_command.is_empty() {
            let ok = spawn_detached(&rule.restart_command);
            log(&format!(
                "rule '{}': killed {} proc(s) ~{}MB, relaunch {}",
                rule.name,
                n,
                mb,
                if ok { "started" } else { "FAILED" }
            ));
            actions.push(format!(
                "rule '{}': restarted {} proc(s) (~{}MB)",
                rule.name, n, mb
            ));
        } else {
            log(&format!(
                "rule '{}': killed {} proc(s) ~{}MB",
                rule.name, n, mb
            ));
            actions.push(format!(
                "rule '{}': killed {} proc(s) (~{}MB)",
                rule.name, n, mb
            ));
        }
    }

    // Non-aggressive tier: at the lower threshold, reap duplicate / orphan / spam
    // pileups automatically (newest spared) — the safe, targeted reclamation.
    let (reap_actions, reap_mb) = auto_reap(snap, cfg);
    reclaimed_mb += reap_mb;
    actions.extend(reap_actions);

    // Aggressive tier: at the critical threshold, kill the largest hog(s) without
    // waiting for a rule or confirmation, restarting configured apps afterwards.
    // Hysteresis: only "armed" once RAM has stayed critical for the configured
    // number of consecutive passes, so a single transient spike never kills.
    let gate = cfg.optimize.auto_act_system_ram_pct;
    let engaged = gate > 0.0 && snap.used_pct >= gate;
    let confirm = cfg.optimize.auto_act_confirm_passes.max(1) as u32;
    let (streak, armed) = aggressive_gate(engaged, meta.aggressive_streak, confirm);
    meta.aggressive_streak = streak;
    let (relief_actions, relief_mb) = auto_relief(snap, cfg, armed, streak, confirm);
    reclaimed_mb += relief_mb;
    actions.extend(relief_actions);

    // Opt-in: tame Microsoft Defender when it's hogging resources for no reason.
    if cfg.optimize.pause_antimalware_when_idle {
        if let Some((msg, mb)) = tame_antimalware(snap, cfg) {
            reclaimed_mb += mb;
            actions.push(msg);
        }
    }

    OptResult {
        actions,
        reclaimed_mb,
    }
}

/// Minimum size a process must reach to be an aggressive-tier auto-kill target —
/// so a critical pass never wastes a kill on something too small to relieve
/// pressure (e.g. when every large process is on the ignore-list).
const MIN_AUTO_KILL_MB: u64 = 300;

/// Update the consecutive-critical-pass streak and decide whether the aggressive
/// relief tier may act this pass. Pure, so the hysteresis is unit-testable.
/// `engaged` = RAM is at/above the gate now; `confirm` = passes required (≥ 1).
/// Returns `(new_streak, armed)`.
fn aggressive_gate(engaged: bool, prev_streak: u32, confirm: u32) -> (u32, bool) {
    let streak = if engaged {
        prev_streak.saturating_add(1)
    } else {
        0
    };
    (streak, engaged && streak >= confirm.max(1))
}

/// Aggressive tier (see `optimize.autoActSystemRamPct`). When system RAM is at or
/// above the configured critical percent (0 disables) AND it has stayed there for
/// `autoActConfirmPasses` consecutive passes (`armed`), kill the largest eligible
/// process(es) to reclaim memory — no rule and no confirmation required. Eligible
/// excludes the ignore-list (the user's lever — browsers/OS processes are ignored
/// by default), the antimalware service, RAM Optimizer itself, pid 0, and anything
/// under `MIN_AUTO_KILL_MB`. Honors `autoActMaxKills` (≥ 1). If a kill takes Claude
/// down it is relaunched (the same liveness guard the reap tier uses). Returns
/// `(messages, MB reclaimed)`; every kill, "holding", and "nothing eligible" is logged.
fn auto_relief(
    snap: &Snapshot,
    cfg: &Config,
    armed: bool,
    streak: u32,
    confirm: u32,
) -> (Vec<String>, u64) {
    let gate = cfg.optimize.auto_act_system_ram_pct;
    if gate <= 0.0 || snap.used_pct < gate {
        return (vec![], 0); // tier not engaged
    }
    if !armed {
        // Engaged, but still inside the hysteresis window — wait it out.
        log(&format!(
            "critical RAM {:.0}% ≥ {:.0}% — holding aggressive kill ({}/{} consecutive passes)",
            snap.used_pct, gate, streak, confirm
        ));
        return (vec![], 0);
    }
    let targets = auto_relief_targets(snap, cfg);
    if targets.is_empty() {
        log(&format!(
            "RAM {:.0}% ≥ {:.0}% critical, but no eligible process ≥ {}MB to auto-kill (all large ones ignored?)",
            snap.used_pct, gate, MIN_AUTO_KILL_MB
        ));
        return (vec![], 0);
    }

    // Before killing, decide whether these kills could take Claude down (a target
    // is Claude, or an ancestor/descendant of it) and capture how to bring it back.
    let guard = crate::guard::plan(snap, &targets, cfg);
    let mut actions = Vec::new();
    let mut reclaimed = 0u64;
    for t in &targets {
        // kill_verified re-checks name + start time, so a reused PID is never hit.
        if kill_verified(&[t]) == 1 {
            reclaimed += t.mem_mb;
            // Restart configured apps (e.g. claude.exe/node.exe/java.exe) so they
            // come back fresh with their leaked RAM reclaimed.
            let restarted = if wants_restart(&t.name, cfg) {
                restart_proc(t)
            } else {
                None
            };
            let tail = match &restarted {
                Some(true) => " → restarted",
                Some(false) => " → restart FAILED",
                None => "",
            };
            log(&format!(
                "critical RAM {:.0}% ≥ {:.0}% → auto-killed {} (pid {}, ~{}MB){}",
                snap.used_pct, gate, t.name, t.pid, t.mem_mb, tail
            ));
            actions.push(format!(
                "critical RAM {:.0}%: auto-killed largest process {} (pid {}, ~{}MB){}",
                snap.used_pct, t.name, t.pid, t.mem_mb, tail
            ));
        }
    }
    // If a kill touched Claude's tree, make sure Claude survived — relaunch it if
    // not. `restartAfterKill` above may have already brought it back; the guard
    // re-checks for ANY live Claude, so it never launches a second copy.
    if let Some(g) = guard {
        if let Some((msg, _ok)) = crate::guard::enforce(&g) {
            log(&format!("critical RAM {:.0}%: {}", snap.used_pct, msg));
            actions.push(format!("critical RAM {:.0}%: {}", snap.used_pct, msg));
        }
    }
    (actions, reclaimed)
}

/// Should this just-killed process be relaunched? True when its name is on
/// `restartAfterKill`, or when that list contains the wildcard `"*"` — meaning
/// "relaunch every app the aggressive tier kills" (e.g. so `chrome.exe`, or any
/// other app, reopens after it's killed to relieve pressure).
fn wants_restart(name: &str, cfg: &Config) -> bool {
    cfg.optimize
        .restart_after_kill
        .iter()
        .any(|n| n == "*" || n.eq_ignore_ascii_case(name))
}

/// How to relaunch `p`: `(program, args)`. Prefers the full exe path so a bare
/// argv[0] like "node" still resolves. A multi-process app's **child** (its argv
/// carries a role flag like `--type=renderer`) can't be started standalone —
/// relaunching it verbatim does nothing useful — so for those we launch the bare
/// executable instead, which reopens the app's main window (e.g. Chrome restores
/// its session). Non-child processes keep their full argv. Pure, so it's testable.
fn relaunch_cmd(p: &Proc) -> Option<(String, Vec<String>)> {
    let program = if !p.exe.is_empty() {
        p.exe.clone()
    } else {
        p.argv.first()?.clone()
    };
    let is_child = p.argv.iter().any(|a| a.starts_with("--type="));
    let args = if !is_child && p.argv.len() > 1 {
        p.argv[1..].to_vec()
    } else {
        Vec::new()
    };
    Some((program, args))
}

/// Relaunch a just-killed process (detached + windowless) per [`relaunch_cmd`].
/// Returns Some(true/false) for success/failure (None = nothing to launch).
/// Shared with the Claude liveness guard (see `crate::guard`).
pub(crate) fn restart_proc(p: &Proc) -> Option<bool> {
    let (program, args) = relaunch_cmd(p)?;
    let mut cmd = hidden_command(&program);
    cmd.args(&args);
    if !p.cwd.is_empty() {
        cmd.current_dir(&p.cwd);
    }
    Some(cmd.spawn().is_ok())
}

/// Non-aggressive tier: when system RAM is at/above `optimize.autoReapSystemRamPct`
/// (0 disables), auto-kill duplicate / orphan / spam pileups (newest spared). The
/// pileup size that counts is **tier-dependent**: `autoReapCount` (e.g. 10) in the
/// band below the aggressive threshold, dropping to `autoReapCountAggressive`
/// (e.g. 5) once RAM is critical — so a maxed-out box reaps smaller pileups too.
/// Targeted and safe: only ever extra instances of one name, never a lone app or
/// the biggest hog. Returns `(messages, MB reclaimed)`.
fn auto_reap(snap: &Snapshot, cfg: &Config) -> (Vec<String>, u64) {
    let o = &cfg.optimize;
    if o.auto_reap_system_ram_pct <= 0.0 || snap.used_pct < o.auto_reap_system_ram_pct {
        return (vec![], 0);
    }
    let aggressive = o.auto_act_system_ram_pct > 0.0 && snap.used_pct >= o.auto_act_system_ram_pct;
    let count = if aggressive {
        o.auto_reap_count_aggressive
    } else {
        o.auto_reap_count
    };
    let want: HashSet<u32> = crate::detect::reap_targets(snap, cfg, count)
        .into_iter()
        .collect();
    if want.is_empty() {
        return (vec![], 0);
    }
    let targets: Vec<&Proc> = snap
        .procs
        .iter()
        .filter(|p| want.contains(&p.pid))
        .collect();
    let mb: u64 = targets.iter().map(|p| p.mem_mb).sum();
    // Before killing, decide whether this reap could take Claude down (a target is
    // Claude, or an ancestor/descendant of it) and capture how to bring it back.
    let guard = crate::guard::plan(snap, &targets, cfg);
    let n = kill_verified(&targets);
    if n == 0 {
        return (vec![], 0);
    }
    let band = if aggressive {
        "aggressive"
    } else {
        "non-aggressive"
    };
    log(&format!(
        "RAM {:.0}% → reaped {} dup/orphan proc(s) (~{}MB, {} ≥{} instances)",
        snap.used_pct, n, mb, band, count
    ));
    let mut actions = vec![format!(
        "RAM {:.0}%: reaped {} dup/orphan proc(s) (~{}MB, ≥{} instances)",
        snap.used_pct, n, mb, count
    )];
    // If the reap touched Claude's process tree, make sure Claude survived it —
    // relaunch from its captured argv + cwd if every instance went down.
    if let Some(g) = guard {
        if let Some((msg, _ok)) = crate::guard::enforce(&g) {
            log(&format!("RAM {:.0}%: {}", snap.used_pct, msg));
            actions.push(format!("RAM {:.0}%: {}", snap.used_pct, msg));
        }
    }
    (actions, mb)
}

/// The aggressive tier's kill targets for this snapshot — pure (no killing), so
/// the "right conditions" policy is unit-testable. Returns empty when the tier is
/// off (`gate == 0`), RAM is below the gate, or nothing eligible is large enough.
/// Eligible = not pid 0, not this process, ≥ `MIN_AUTO_KILL_MB`, not on the
/// ignore-list, not the antimalware service — largest first, capped at
/// `autoActMaxKills`.
fn auto_relief_targets<'a>(snap: &'a Snapshot, cfg: &Config) -> Vec<&'a Proc> {
    let gate = cfg.optimize.auto_act_system_ram_pct;
    if gate <= 0.0 || snap.used_pct < gate {
        return vec![];
    }
    let ignore: HashSet<String> = cfg
        .thresholds
        .ignore_names
        .iter()
        .map(|s| s.to_lowercase())
        .collect();
    let self_pid = std::process::id();
    // Claude (and its linked process tree) is the priority to keep alive: never
    // pick it as a relief target, so a pass kills other hogs (e.g. Chrome) first
    // even when Claude is technically the biggest. Empty unless guarding is on.
    let protect = crate::guard::protected_pids(snap, cfg);
    let mut cands: Vec<&Proc> = snap
        .procs
        .iter()
        .filter(|p| p.pid != 0 && p.pid != self_pid)
        .filter(|p| p.mem_mb >= MIN_AUTO_KILL_MB)
        .filter(|p| !ignore.contains(&p.name.to_lowercase()))
        .filter(|p| !crate::critical::is_critical_system_process(&p.name))
        .filter(|p| !windefend::is_antimalware(&p.name))
        .filter(|p| !protect.contains(&p.pid))
        .collect();
    cands.sort_by_key(|p| std::cmp::Reverse(p.mem_mb));
    let max = cfg.optimize.auto_act_max_kills.max(1);
    cands.into_iter().take(max).collect()
}

/// The blocklist's kill targets for this snapshot — pure (no killing), so the
/// policy is unit-testable. Every live process whose name is on
/// `optimize.blockNames` (case-insensitive), EXCEPT the OS-critical floor and
/// RAM Optimizer itself (so a typo can't brick the box). Deliberately ignores
/// `ignoreNames`/`noReapNames`/Claude-protection — blocking is an explicit override.
fn block_targets<'a>(snap: &'a Snapshot, cfg: &Config) -> Vec<&'a Proc> {
    let block: HashSet<String> = cfg
        .optimize
        .block_names
        .iter()
        .map(|s| s.to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if block.is_empty() {
        return vec![];
    }
    let self_pid = std::process::id();
    snap.procs
        .iter()
        .filter(|p| p.pid != 0 && p.pid != self_pid)
        .filter(|p| block.contains(&p.name.to_lowercase()))
        .filter(|p| !crate::critical::is_critical_system_process(&p.name))
        .collect()
}

/// Kill every blocklisted process on sight (no RAM gate, no restart). Returns
/// `(messages, MB reclaimed)`; the kill is logged with the distinct names hit.
fn run_blocklist(snap: &Snapshot, cfg: &Config) -> (Vec<String>, u64) {
    let targets = block_targets(snap, cfg);
    if targets.is_empty() {
        return (vec![], 0);
    }
    let mb: u64 = targets.iter().map(|p| p.mem_mb).sum();
    let mut names: Vec<String> = targets.iter().map(|p| p.name.clone()).collect();
    names.sort();
    names.dedup();
    let n = kill_verified(&targets);
    if n == 0 {
        return (vec![], 0);
    }
    let list = names.join(", ");
    log(&format!("blocklist → killed {n} proc(s) (~{mb}MB): {list}"));
    (
        vec![format!("blocked: killed {n} proc(s) (~{mb}MB): {list}")],
        mb,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::{Proc, Snapshot};
    use crate::config::Config;

    fn proc(pid: u32, name: &str, mem: u64) -> Proc {
        Proc {
            pid,
            ppid: None,
            name: name.into(),
            mem_mb: mem,
            cpu: 0.0,
            start: pid as u64,
            cmd: String::new(),
            exe: String::new(),
            argv: Vec::new(),
            cwd: String::new(),
        }
    }
    fn snap(used_pct: f64, procs: Vec<Proc>) -> Snapshot {
        Snapshot {
            epoch: 0,
            total_mb: 16000,
            used_mb: (16000.0 * used_pct / 100.0) as u64,
            used_pct,
            procs,
        }
    }
    fn cfg_with(gate: f64, max: usize) -> Config {
        let mut c = Config::default();
        c.optimize.auto_act_system_ram_pct = gate;
        c.optimize.auto_act_max_kills = max;
        c
    }

    #[test]
    fn no_action_below_gate() {
        let s = snap(90.0, vec![proc(100, "node.exe", 4000)]);
        assert!(auto_relief_targets(&s, &cfg_with(95.0, 1)).is_empty());
    }

    #[test]
    fn tier_off_when_gate_zero_even_at_critical_ram() {
        let s = snap(99.0, vec![proc(100, "node.exe", 4000)]);
        assert!(auto_relief_targets(&s, &cfg_with(0.0, 1)).is_empty());
    }

    #[test]
    fn picks_largest_eligible_skipping_ignored_av_and_small() {
        let s = snap(
            96.0,
            vec![
                proc(100, "chrome.exe", 9000),  // ignore-listed by default
                proc(101, "MsMpEng.exe", 8000), // antimalware (and ignored)
                proc(102, "node.exe", 4000),    // largest eligible
                proc(103, "java.exe", 2000),    // eligible
                proc(104, "tiny.exe", 100),     // under MIN_AUTO_KILL_MB
            ],
        );
        let t = auto_relief_targets(&s, &cfg_with(95.0, 1));
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].name, "node.exe");
    }

    #[test]
    fn respects_max_kills_largest_first() {
        let s = snap(
            97.0,
            vec![
                proc(102, "node.exe", 4000),
                proc(103, "java.exe", 3000),
                proc(104, "app.exe", 2000),
            ],
        );
        let t = auto_relief_targets(&s, &cfg_with(95.0, 2));
        assert_eq!(
            t.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["node.exe", "java.exe"]
        );
    }

    #[test]
    fn never_targets_critical_os_process_even_with_empty_ignore_list() {
        // Empty ignore-list ("exception is no one") must NOT expose OS-critical
        // processes — the hardcoded floor keeps svchost/System safe; the browser
        // (now un-ignored) is the eligible target instead.
        let mut c = cfg_with(95.0, 1);
        c.thresholds.ignore_names = vec![];
        let s = snap(
            97.0,
            vec![
                proc(4, "System", 9000),       // critical — never killable
                proc(8, "svchost.exe", 5000),  // critical — never killable
                proc(100, "chrome.exe", 4000), // un-ignored now → eligible
            ],
        );
        let t = auto_relief_targets(&s, &c);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].name, "chrome.exe");
    }

    #[test]
    fn relief_protects_claude_tree_and_kills_other_hog() {
        // Claude is the biggest, but it's the priority to keep alive — relief must
        // skip it and kill the largest NON-Claude hog (Chrome) instead.
        let mut c = cfg_with(95.0, 1);
        c.thresholds.ignore_names = vec![]; // so chrome is eligible
        let s = snap(
            96.0,
            vec![
                proc(100, "claude.exe", 5000), // biggest — protected
                proc(101, "chrome.exe", 4000), // largest killable
                proc(102, "node.exe", 1000),
            ],
        );
        let t = auto_relief_targets(&s, &c);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].name, "chrome.exe");
    }

    #[test]
    fn block_targets_kills_listed_but_never_critical() {
        let mut c = Config::default();
        c.optimize.block_names = vec!["BloatApp.exe".into(), "svchost.exe".into()];
        let s = snap(
            50.0, // no RAM gate — blocklist acts regardless
            vec![
                proc(100, "bloatapp.exe", 200), // listed (case-insensitive) → target
                proc(8, "svchost.exe", 500),    // listed but OS-critical → spared
                proc(101, "other.exe", 900),    // not listed → spared
            ],
        );
        let t: Vec<&str> = block_targets(&s, &c)
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(t, ["bloatapp.exe"]);
        // Empty blocklist → nothing.
        c.optimize.block_names = vec![];
        assert!(block_targets(&s, &c).is_empty());
    }

    #[test]
    fn relaunch_strips_child_process_args_keeps_normal_argv() {
        // A browser child (--type=...) relaunches as the bare exe so it reopens.
        let mut child = proc(1, "chrome.exe", 400);
        child.exe = "C:/c/chrome.exe".into();
        child.argv = vec![
            "chrome.exe".into(),
            "--type=renderer".into(),
            "--lang=en".into(),
        ];
        let (prog, args) = relaunch_cmd(&child).unwrap();
        assert_eq!(prog, "C:/c/chrome.exe");
        assert!(args.is_empty());
        // A normal app keeps its full argv.
        let mut node = proc(2, "node.exe", 400);
        node.exe = "C:/node.exe".into();
        node.argv = vec!["node".into(), "cli.js".into(), "--flag".into()];
        let (_p, a) = relaunch_cmd(&node).unwrap();
        assert_eq!(a, vec!["cli.js".to_string(), "--flag".to_string()]);
    }

    #[test]
    fn nothing_eligible_when_all_large_are_ignored() {
        let s = snap(
            98.0,
            vec![proc(100, "chrome.exe", 9000), proc(101, "msedge.exe", 8000)],
        );
        assert!(auto_relief_targets(&s, &cfg_with(95.0, 1)).is_empty());
    }

    #[test]
    fn aggressive_gate_waits_for_consecutive_passes() {
        // confirm = 2: first critical pass arms nothing, the second does.
        let (s1, a1) = aggressive_gate(true, 0, 2);
        assert_eq!((s1, a1), (1, false));
        let (s2, a2) = aggressive_gate(true, s1, 2);
        assert_eq!((s2, a2), (2, true));
        // Staying critical keeps it armed.
        let (s3, a3) = aggressive_gate(true, s2, 2);
        assert_eq!((s3, a3), (3, true));
        // A dip below the gate resets the streak — the timer starts over.
        let (s4, a4) = aggressive_gate(false, s3, 2);
        assert_eq!((s4, a4), (0, false));
    }

    #[test]
    fn aggressive_gate_confirm_one_acts_immediately() {
        // confirm clamps to ≥ 1, so 1 (and 0) means "act on the first pass".
        assert_eq!(aggressive_gate(true, 0, 1), (1, true));
        assert_eq!(aggressive_gate(true, 0, 0), (1, true));
        // Not engaged never arms, regardless of prior streak.
        assert_eq!(aggressive_gate(false, 5, 1), (0, false));
    }

    #[test]
    fn wants_restart_is_case_insensitive() {
        let mut c = Config::default();
        c.optimize.restart_after_kill = vec!["claude.exe".into(), "node.exe".into()];
        assert!(wants_restart("Claude.exe", &c));
        assert!(wants_restart("node.exe", &c));
        assert!(!wants_restart("java.exe", &c));
    }

    #[test]
    fn wants_restart_wildcard_relaunches_any_app() {
        let mut c = Config::default();
        c.optimize.restart_after_kill = vec!["*".into()];
        // "*" means relaunch whatever the aggressive tier kills.
        assert!(wants_restart("chrome.exe", &c));
        assert!(wants_restart("anything.exe", &c));
        // An empty list never restarts anything.
        c.optimize.restart_after_kill = vec![];
        assert!(!wants_restart("chrome.exe", &c));
    }

    #[test]
    fn antimalware_hot_threshold_falls_back_then_honors_config() {
        let mut c = Config::default();
        c.thresholds.high_ram_mb = 1500;
        // 0 → legacy 2× highRamMB.
        c.optimize.antimalware_hot_ram_mb = 0;
        assert_eq!(antimalware_hot_ram_mb(&c), 3000);
        // A configured value wins, letting the tame fire at a smaller footprint.
        c.optimize.antimalware_hot_ram_mb = 250;
        assert_eq!(antimalware_hot_ram_mb(&c), 250);
    }

    #[test]
    fn antimalware_pause_pct_falls_back_to_alert_then_honors_config() {
        let mut c = Config::default();
        c.thresholds.system_ram_pct_alert = 85.0;
        // 0 → the gentle (non-aggressive) systemRamPctAlert band.
        c.optimize.antimalware_pause_system_ram_pct = 0.0;
        assert_eq!(antimalware_pause_ram_pct(&c), 85.0);
        // A configured value wins.
        c.optimize.antimalware_pause_system_ram_pct = 80.0;
        assert_eq!(antimalware_pause_ram_pct(&c), 80.0);
    }
}

/// The RAM footprint (MB) at/above which the antimalware service counts as hot
/// enough to tame: the configured `antimalwareHotRamMB`, or — when that's `0` —
/// the original conservative `2 × highRamMB`. Pure, so it's unit-testable.
fn antimalware_hot_ram_mb(cfg: &Config) -> u64 {
    let configured = cfg.optimize.antimalware_hot_ram_mb;
    if configured > 0 {
        configured
    } else {
        cfg.thresholds.high_ram_mb.saturating_mul(2)
    }
}

/// The system-RAM% at/above which the antimalware service may be tamed: the
/// configured `antimalwarePauseSystemRamPct`, or — when `0` — the gentle
/// `thresholds.systemRamPctAlert` (the non-aggressive band). Pure/testable.
fn antimalware_pause_ram_pct(cfg: &Config) -> f64 {
    let configured = cfg.optimize.antimalware_pause_system_ram_pct;
    if configured > 0.0 {
        configured
    } else {
        cfg.thresholds.system_ram_pct_alert
    }
}

/// Opt-in antimalware taming (see `windefend`). Fires only when ALL hold:
///   1. system RAM is at/above `antimalwarePauseSystemRamPct` (default
///      `systemRamPctAlert`, the non-aggressive band), and
///   2. the antimalware service is running hot right now (≥ `antimalwareHotRamMB`,
///      default `2 × highRamMB`, or ≥ `highCpuPct`), and
///   3. Defender confirms there are **no active threats**.
///
/// On confirmed threats — or when threat status can't be determined — the service
/// is left running (fail safe). Every branch is logged. Returns `(message, MB
/// freed)` when it had something to report, else `None`.
fn tame_antimalware(snap: &crate::collect::Snapshot, cfg: &Config) -> Option<(String, u64)> {
    let t = &cfg.thresholds;

    // (1) System RAM must be high (non-aggressive band by default).
    if snap.used_pct < antimalware_pause_ram_pct(cfg) {
        return None;
    }
    // (2) The antimalware service must be running hot (RAM at/above the configured
    //     threshold, or CPU at/above highCpuPct).
    let hot_ram = antimalware_hot_ram_mb(cfg);
    let am = snap.procs.iter().find(|p| {
        windefend::is_antimalware(&p.name) && (p.mem_mb >= hot_ram || p.cpu >= t.high_cpu_pct)
    })?;

    // (3) Only disable AV when Defender confirms there are no active threats.
    match windefend::threats_present() {
        ThreatStatus::Present => {
            log("antimalware hot under RAM pressure, but Defender reports ACTIVE THREATS — left running");
            None
        }
        ThreatStatus::Unknown => {
            log("antimalware hot under RAM pressure, but threat status unconfirmed — left running");
            None
        }
        ThreatStatus::Clear => match windefend::pause_service() {
            Ok(detail) => {
                log(&format!(
                    "antimalware {} ({}MB, {:.0}% CPU) hot under RAM pressure, no active threats → stopped: {}",
                    am.name, am.mem_mb, am.cpu, detail
                ));
                Some((
                    format!(
                        "paused antimalware service — RAM {:.0}%, no active threats ({}, ~{}MB): {}",
                        snap.used_pct, am.name, am.mem_mb, detail
                    ),
                    am.mem_mb,
                ))
            }
            Err(e) => {
                // Tell the user WHY it failed and exactly how to allow it — the two
                // blockers (Tamper Protection, elevation) can't be cleared in code.
                let hint = if windefend::tamper_protection_on() == Some(true) {
                    format!(" {}", windefend::pause_howto())
                } else {
                    " (run RAM Optimizer elevated — re-register the task with `install-windows.ps1 -Elevated` — so it has rights to stop a system service)".to_string()
                };
                log(&format!(
                    "antimalware hot, no active threats → stop FAILED: {e}{hint}"
                ));
                Some((
                    format!(
                        "antimalware stop failed ({} still running): {}{}",
                        am.name, e, hint
                    ),
                    0,
                ))
            }
        },
    }
}
