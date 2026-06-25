//! Claude liveness guard for the optimizer's automatic kill tiers. Claude Code
//! runs as one or more `claude.exe` / `node.exe` processes; a duplicate/orphan
//! reap can sweep one up (the newest is spared, but Claude isn't always the
//! newest) or orphan it by reaping a parent, and the aggressive tier can kill
//! Claude outright if it's the biggest hog. When a kill touches Claude's process
//! tree, this checks — right after the kills — whether ANY Claude instance is
//! still alive, and relaunches the primary from its captured argv + working dir
//! if not. Opt-in via `optimize.guardClaude`; markers in `optimize.claudeMarkers`
//! (default "claude"). Used by both `optimize::auto_reap` and `auto_relief`.
use crate::collect::{Proc, Snapshot};
use crate::config::Config;
use std::collections::{HashMap, HashSet};
use sysinfo::{ProcessRefreshKind, System};

/// A planned guard: the Claude process to relaunch if no Claude survives the
/// kills, plus the markers used to recognize a live Claude afterwards.
pub struct Guard {
    primary: Proc,
    markers: Vec<String>,
}

/// Does this process look like Claude? Markers (already lowercased) are matched
/// against the process name AND its command line / exe path, so both the native
/// `claude.exe` and a `node.exe` running Claude Code are recognized.
fn is_claude(p: &Proc, markers: &[String]) -> bool {
    let name = p.name.to_lowercase();
    let hay = format!("{} {}", p.cmd, p.exe).to_lowercase();
    markers
        .iter()
        .any(|m| name.contains(m.as_str()) || hay.contains(m.as_str()))
}

/// PIDs in Claude's process tree: every Claude instance plus its live ancestors
/// and descendants. A reap touching any of these "could affect Claude".
fn claude_tree(snap: &Snapshot, claude: &[&Proc]) -> HashSet<u32> {
    let live: HashSet<u32> = snap.procs.iter().map(|p| p.pid).collect();
    let parent: HashMap<u32, u32> = snap
        .procs
        .iter()
        .filter_map(|p| p.ppid.map(|pp| (p.pid, pp)))
        .collect();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, pp) in &parent {
        children.entry(*pp).or_default().push(*pid);
    }
    let mut tree: HashSet<u32> = HashSet::new();
    for c in claude {
        tree.insert(c.pid);
        // Ancestors: walk parent links (bounded, so a cycle can't spin forever).
        let mut cur = c.pid;
        for _ in 0..64 {
            match parent.get(&cur) {
                Some(&pp) if pp != 0 && live.contains(&pp) => {
                    tree.insert(pp);
                    cur = pp;
                }
                _ => break,
            }
        }
        // Descendants: BFS over the children map (insert-guarded against revisits).
        let mut stack = vec![c.pid];
        while let Some(pid) = stack.pop() {
            if let Some(kids) = children.get(&pid) {
                for &k in kids {
                    if tree.insert(k) {
                        stack.push(k);
                    }
                }
            }
        }
    }
    tree
}

/// PIDs of Claude's live process tree to **protect** from the optimizer's
/// automatic kill tiers — so a pass keeps Claude (and its linked helpers) alive as
/// long as possible and kills other hogs first. Empty when guarding is off, there
/// are no markers, or no Claude is running. Reuses the same markers + tree walk as
/// the liveness guard, so "what counts as Claude" is defined in one place.
pub fn protected_pids(snap: &Snapshot, cfg: &Config) -> HashSet<u32> {
    let o = &cfg.optimize;
    if !o.guard_claude {
        return HashSet::new();
    }
    let markers: Vec<String> = o
        .claude_markers
        .iter()
        .map(|m| m.to_lowercase())
        .filter(|m| !m.is_empty())
        .collect();
    if markers.is_empty() {
        return HashSet::new();
    }
    let claude: Vec<&Proc> = snap
        .procs
        .iter()
        .filter(|p| is_claude(p, &markers))
        .collect();
    if claude.is_empty() {
        return HashSet::new();
    }
    claude_tree(snap, &claude)
}

/// The Claude instance to relaunch: the root-most one (its parent is not itself
/// Claude), preferring a name match over a cmd-only match, then the oldest start
/// (the long-lived main process rather than a short-lived helper).
fn pick_primary<'a>(claude: &[&'a Proc], markers: &[String]) -> Option<&'a Proc> {
    let pids: HashSet<u32> = claude.iter().map(|p| p.pid).collect();
    let mut roots: Vec<&Proc> = claude
        .iter()
        .copied()
        .filter(|p| !matches!(p.ppid, Some(pp) if pids.contains(&pp)))
        .collect();
    if roots.is_empty() {
        roots = claude.to_vec();
    }
    roots.sort_by_key(|p| {
        let name = p.name.to_lowercase();
        let name_match = markers.iter().any(|m| name.contains(m.as_str()));
        (!name_match, p.start)
    });
    roots.into_iter().next()
}

/// Decide whether a reap warrants guarding Claude. Returns `Some(Guard)` only when
/// guarding is enabled, at least one Claude instance is alive, and the reap
/// `targets` touch Claude's process tree — so an unrelated reap never arms a
/// relaunch. Pure (reads the pre-kill snapshot only); call before the kills.
pub fn plan(snap: &Snapshot, targets: &[&Proc], cfg: &Config) -> Option<Guard> {
    let o = &cfg.optimize;
    if !o.guard_claude {
        return None;
    }
    let markers: Vec<String> = o
        .claude_markers
        .iter()
        .map(|m| m.to_lowercase())
        .filter(|m| !m.is_empty())
        .collect();
    if markers.is_empty() {
        return None;
    }
    let claude: Vec<&Proc> = snap
        .procs
        .iter()
        .filter(|p| is_claude(p, &markers))
        .collect();
    if claude.is_empty() {
        return None;
    }
    let tree = claude_tree(snap, &claude);
    if !targets.iter().any(|t| tree.contains(&t.pid)) {
        return None; // reap doesn't touch Claude's tree
    }
    let primary = pick_primary(&claude, &markers)?.clone();
    Some(Guard { primary, markers })
}

/// Is ANY Claude instance alive right now (matched by the same markers as `plan`,
/// against process name AND command line / exe path)? A fresh scan, so a Claude
/// that the aggressive tier's `restartAfterKill` already relaunched counts as a
/// survivor — which is what keeps the guard from launching a second copy.
fn any_claude_alive(markers: &[String]) -> bool {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::everything());
    sys.processes().values().any(|p| {
        let name = p.name().to_lowercase();
        let exe = p
            .exe()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_default();
        let hay = format!("{} {}", p.cmd().join(" "), exe).to_lowercase();
        markers
            .iter()
            .any(|m| name.contains(m.as_str()) || hay.contains(m.as_str()))
    })
}

/// Run the guard after the kills: if no Claude instance is alive any more,
/// relaunch the primary from its captured argv + cwd. Returns a message + whether
/// the relaunch started, or `None` when a Claude is still up (nothing to do).
pub fn enforce(guard: &Guard) -> Option<(String, bool)> {
    // Let the just-killed processes leave the process table before judging
    // liveness, so a lingering zombie isn't mistaken for a survivor (and Claude's
    // restart wrongly skipped). Negligible against a multi-minute scheduled pass.
    std::thread::sleep(std::time::Duration::from_millis(300));
    if any_claude_alive(&guard.markers) {
        return None;
    }
    let ok = crate::optimize::restart_proc(&guard.primary).unwrap_or(false);
    Some((
        format!(
            "reap took Claude down ({}, pid {}) — relaunch {}",
            guard.primary.name,
            guard.primary.pid,
            if ok { "started" } else { "FAILED" }
        ),
        ok,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, ppid: Option<u32>, name: &str, cmd: &str) -> Proc {
        Proc {
            pid,
            ppid,
            name: name.into(),
            mem_mb: 100,
            cpu: 0.0,
            start: pid as u64,
            cmd: cmd.into(),
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
    fn cfg() -> Config {
        let mut c = Config::default();
        c.optimize.guard_claude = true;
        c.optimize.claude_markers = vec!["claude".into()];
        c
    }
    fn refs<'a>(s: &'a Snapshot, pids: &[u32]) -> Vec<&'a Proc> {
        s.procs.iter().filter(|p| pids.contains(&p.pid)).collect()
    }

    #[test]
    fn is_claude_matches_name_and_cmd_not_unrelated() {
        let m = vec!["claude".to_string()];
        assert!(is_claude(&proc(1, None, "claude.exe", ""), &m));
        assert!(is_claude(
            &proc(2, None, "node.exe", "node x/claude-code/cli.js"),
            &m
        ));
        assert!(!is_claude(&proc(3, None, "node.exe", "node server.js"), &m));
    }

    #[test]
    fn none_when_disabled_or_no_markers() {
        let s = snap(vec![proc(1, None, "claude.exe", "")]);
        let t = refs(&s, &[1]);
        let mut c = cfg();
        c.optimize.guard_claude = false;
        assert!(plan(&s, &t, &c).is_none());
        let mut c2 = cfg();
        c2.optimize.claude_markers = vec![];
        assert!(plan(&s, &t, &c2).is_none());
    }

    #[test]
    fn none_when_no_claude_or_reap_misses_tree() {
        // No Claude at all.
        let s = snap(vec![proc(1, None, "node.exe", "node a.js")]);
        assert!(plan(&s, &refs(&s, &[1]), &cfg()).is_none());
        // Claude present, but the reap targets an unrelated process.
        let s2 = snap(vec![
            proc(1, None, "claude.exe", ""),
            proc(2, None, "chrome.exe", ""),
        ]);
        assert!(plan(&s2, &refs(&s2, &[2]), &cfg()).is_none());
    }

    #[test]
    fn protected_pids_covers_claude_and_descendants_only() {
        let s = snap(vec![
            proc(10, None, "claude.exe", ""),
            proc(11, Some(10), "node.exe", "node mcp-server"), // child of claude
            proc(12, None, "chrome.exe", ""),                  // unrelated
        ]);
        let pids = protected_pids(&s, &cfg());
        assert!(pids.contains(&10)); // claude itself
        assert!(pids.contains(&11)); // its linked child
        assert!(!pids.contains(&12)); // unrelated app stays killable
                                      // Disabling the guard protects nothing.
        let mut off = cfg();
        off.optimize.guard_claude = false;
        assert!(protected_pids(&s, &off).is_empty());
    }

    #[test]
    fn some_when_target_is_claude() {
        let s = snap(vec![
            proc(10, None, "node.exe", "node x/claude-code/cli.js"),
            proc(11, None, "node.exe", "node x/claude-code/cli.js"),
        ]);
        let g = plan(&s, &refs(&s, &[10]), &cfg()).expect("guard armed");
        // The primary to relaunch is the oldest root Claude (pid 10), and the
        // markers are carried through so the guard can spot a live Claude later.
        assert_eq!(g.primary.pid, 10);
        assert_eq!(g.markers, vec!["claude".to_string()]);
    }

    #[test]
    fn some_when_target_is_ancestor_of_claude() {
        // pid 5 (the reaped node) is the parent of the Claude node pid 6.
        let s = snap(vec![
            proc(5, None, "node.exe", "node launcher.js"),
            proc(6, Some(5), "node.exe", "node x/claude-code/cli.js"),
        ]);
        assert!(plan(&s, &refs(&s, &[5]), &cfg()).is_some());
    }

    #[test]
    fn primary_prefers_named_root_then_oldest() {
        // Two Claude instances: a cmd-only child and a name-matching root.
        let claude = vec![
            proc(20, None, "claude.exe", ""), // name match, root
            proc(21, Some(20), "node.exe", "node claude-code/cli"), // cmd-only child
        ];
        let refs: Vec<&Proc> = claude.iter().collect();
        let m = vec!["claude".to_string()];
        assert_eq!(pick_primary(&refs, &m).unwrap().pid, 20);
    }
}
