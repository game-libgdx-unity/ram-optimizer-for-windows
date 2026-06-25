//! Rule matching shared by detection (alerts) and the optimizer (kill/restart).
use crate::collect::{Proc, Snapshot};
use crate::config::{Match, Rule};

/// Does this process satisfy the match conditions? Requires at least one condition
/// (an empty match never matches, so a misconfigured rule can't hit everything).
pub fn matches(p: &Proc, m: &Match) -> bool {
    let mut any = false;
    if let Some(n) = &m.name {
        any = true;
        if !p.name.eq_ignore_ascii_case(n) {
            return false;
        }
    }
    if let Some(pc) = &m.path_contains {
        any = true;
        if !p.exe.to_lowercase().contains(&pc.to_lowercase()) {
            return false;
        }
    }
    if let Some(cc) = &m.cmd_contains {
        any = true;
        if !p.cmd.to_lowercase().contains(&cc.to_lowercase()) {
            return false;
        }
    }
    any
}

/// The processes a rule should act on right now, or empty if the rule does not fire.
/// Honors the system-RAM gate, per-process vs group thresholds, and `spare_newest`.
pub fn targets<'a>(rule: &Rule, snap: &'a Snapshot) -> Vec<&'a Proc> {
    if snap.used_pct < rule.when_system_ram_pct {
        return vec![];
    }
    let matched: Vec<&Proc> = snap
        .procs
        .iter()
        .filter(|p| matches(p, &rule.match_))
        .collect();
    if matched.is_empty() {
        return vec![];
    }

    let has_ram = rule.when_proc_ram_mb.is_some();
    let has_cpu = rule.when_proc_cpu_pct.is_some();

    let mut hits: Vec<&Proc> = if !has_ram && !has_cpu {
        // No resource condition: fire on mere presence (still gated by system RAM%).
        matched
    } else if rule.group {
        let total: u64 = matched.iter().map(|p| p.mem_mb).sum();
        let max_cpu = matched.iter().map(|p| p.cpu).fold(0.0_f64, f64::max);
        let ram_ok = rule.when_proc_ram_mb.is_some_and(|t| total >= t);
        let cpu_ok = rule.when_proc_cpu_pct.is_some_and(|t| max_cpu >= t);
        if ram_ok || cpu_ok {
            matched
        } else {
            vec![]
        }
    } else {
        matched
            .into_iter()
            .filter(|p| {
                let ram_ok = rule.when_proc_ram_mb.is_some_and(|t| p.mem_mb >= t);
                let cpu_ok = rule.when_proc_cpu_pct.is_some_and(|t| p.cpu >= t);
                ram_ok || cpu_ok
            })
            .collect()
    };

    if rule.spare_newest && hits.len() > 1 {
        if let Some(newest) = hits.iter().max_by_key(|p| p.start).map(|p| p.pid) {
            hits.retain(|p| p.pid != newest);
        }
    }
    hits
}

/// Total MB across a set of processes (for messages).
pub fn total_mb(ps: &[&Proc]) -> u64 {
    ps.iter().map(|p| p.mem_mb).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::Snapshot;
    use crate::config::{Match, Rule};

    fn proc(name: &str, mem: u64, start: u64) -> Proc {
        Proc {
            pid: start as u32,
            ppid: None,
            name: name.into(),
            mem_mb: mem,
            cpu: 0.0,
            start,
            cmd: String::new(),
            exe: String::new(),
            argv: Vec::new(),
            cwd: String::new(),
        }
    }

    #[test]
    fn match_name_is_case_insensitive() {
        let p = proc("Chrome.exe", 100, 1);
        let m = Match {
            name: Some("chrome.exe".into()),
            ..Default::default()
        };
        assert!(matches(&p, &m));
    }

    #[test]
    fn empty_match_never_matches() {
        assert!(!matches(&proc("x", 1, 1), &Match::default()));
    }

    #[test]
    fn targets_apply_threshold_and_spare_newest() {
        let snap = Snapshot {
            epoch: 0,
            total_mb: 16000,
            used_mb: 8000,
            used_pct: 50.0,
            procs: vec![
                proc("app.exe", 2500, 10),
                proc("app.exe", 2600, 20), // newest among over-threshold hits
                proc("app.exe", 100, 30),  // under threshold -> not a hit
            ],
        };
        let rule = Rule {
            name: "r".into(),
            match_: Match {
                name: Some("app.exe".into()),
                ..Default::default()
            },
            when_proc_ram_mb: Some(2000),
            action: "kill".into(),
            spare_newest: true,
            ..Default::default()
        };
        let t = targets(&rule, &snap);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].start, 10); // newest hit (start 20) spared
    }

    #[test]
    fn system_gate_blocks_when_below() {
        let snap = Snapshot {
            epoch: 0,
            total_mb: 16000,
            used_mb: 8000,
            used_pct: 50.0,
            procs: vec![proc("app.exe", 3000, 1)],
        };
        let rule = Rule {
            name: "r".into(),
            match_: Match {
                name: Some("app.exe".into()),
                ..Default::default()
            },
            when_proc_ram_mb: Some(2000),
            when_system_ram_pct: 90.0,
            action: "kill".into(),
            ..Default::default()
        };
        assert!(targets(&rule, &snap).is_empty()); // 50% < 90% gate
    }
}
