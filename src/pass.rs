//! One monitoring pass, shared by the headless scheduled run (`main.rs`) and the
//! dashboard's manual triggers (`ui.rs`). Collect → detect → (optionally) act →
//! measure → (optionally) escalate to AI → record. Every pass appends one
//! structured record to `~/.ram-optimizer/runs.jsonl` (see `runlog`).
use crate::actions::{self, Proposal};
use crate::config::Config;
use crate::detect::Finding;
use crate::runlog::{self, AiRec, FindingRec, RunRecord};
use crate::{ai, alert, collect, detect, optimize, state};
use std::collections::HashMap;
use std::time::Instant;

pub struct PassOpts {
    /// Apply kill/restart rule actions (gated again by `optimize.enabled`).
    pub act: bool,
    /// Scheduled AI escalation (respects `ai.enabled` + the rate limit).
    pub escalate: bool,
    /// On-demand AI now, ignoring the rate limit (dashboard "Ask AI").
    pub force_ai: bool,
    /// Emit OS toast + log alerts.
    pub alert: bool,
    pub trigger: String,
}

impl PassOpts {
    /// What the OS scheduler runs: act per config, escalate, and alert.
    pub fn scheduled(act: bool) -> Self {
        PassOpts {
            act,
            escalate: true,
            force_ai: false,
            alert: true,
            trigger: "scheduled".into(),
        }
    }
}

/// Run one pass and return its record (already appended to runs.jsonl).
pub fn run_pass(cfg: &Config, opts: &PassOpts) -> RunRecord {
    let t0 = Instant::now();
    let prev = state::load_prev();
    let mut meta = state::load_meta();

    let snap = collect::collect();
    let findings = detect::analyze(&snap, prev.as_ref(), cfg);

    // Suppress OS popups unless the machine is under memory pressure, when the user
    // has opted into that (alerts.onlyUnderRamPressure). Findings are still logged.
    let allow_toast =
        !cfg.alerts.only_under_ram_pressure || snap.used_pct >= cfg.thresholds.system_ram_pct_alert;

    // Optimizer (kill/restart). Only when asked AND the master switch is on.
    let opt = if opts.act {
        optimize::run(&snap, cfg, &mut meta)
    } else {
        optimize::OptResult::default()
    };
    if !opt.actions.is_empty() && opts.alert && cfg.alerts.toast && allow_toast {
        alert::notify("RAM Optimizer reclaimed resources", &opt.actions.join("\n"));
    }

    // "After" memory — a cheap memory-only refresh (no process enumeration).
    let after = collect::mem_snapshot();
    let reclaimed_mb = opt.reclaimed_mb;
    let total_mb = snap.total_mb.max(1);
    let reduced_pct = reclaimed_mb as f64 / total_mb as f64 * 100.0;

    let self_pid = std::process::id();
    let self_cpu = snap
        .procs
        .iter()
        .find(|p| p.pid == self_pid)
        .map(|p| (p.cpu * 10.0).round() / 10.0)
        .unwrap_or(0.0);

    // Core-pass duration is measured here, BEFORE any (slow, optional) AI call,
    // so the metric reflects the optimizer's own cost — not network latency.
    let duration_ms = t0.elapsed().as_millis() as u64;

    // AI escalation.
    let mut ai_rec: Option<AiRec> = None;
    let mut strategies = Vec::new();
    if opts.escalate {
        if let Some(out) = ai::maybe_escalate(&findings, cfg, &mut meta) {
            ai_rec = Some(out.rec);
            strategies = out.strategies;
        }
    } else if opts.force_ai {
        if cfg.ai.enabled {
            if let Some(out) = ai::force_escalate(&findings, cfg) {
                ai_rec = Some(out.rec);
                strategies = out.strategies;
            }
        } else {
            // AI disabled: still hand back the generated prompt to copy elsewhere.
            let prompt = ai::build_prompt_text(&findings, cfg);
            ai_rec = Some(AiRec {
                provider: "none (AI disabled — prompt only)".into(),
                model: String::new(),
                prompt_chars: prompt.chars().count(),
                prompt,
                advice: String::new(),
            });
        }
    }

    if opts.alert && !findings.is_empty() {
        let advice = ai_rec
            .as_ref()
            .map(|a| a.advice.as_str())
            .filter(|s| !s.is_empty());
        alert::emit(&findings, advice, cfg, &mut meta, allow_toast);
    }

    state::save_meta(&meta);
    state::save_snapshot(&snap);

    // Confirm-to-act: turn actionable findings into proposals the user must
    // approve. Nothing here is executed automatically — that's the safety model
    // for heuristic/AI-suggested kills (config rules are the pre-authorized path).
    let pid_info: HashMap<u32, (String, u64, u64)> = snap
        .procs
        .iter()
        .map(|p| (p.pid, (p.name.clone(), p.mem_mb, p.start)))
        .collect();
    let ai_hinted = ai_rec
        .as_ref()
        .map(|a| !a.advice.is_empty())
        .unwrap_or(false);
    let mut proposals = Vec::new();
    for f in &findings {
        for &pid in &f.pids {
            if let Some((name, mem, start)) = pid_info.get(&pid) {
                proposals.push(Proposal {
                    id: format!("{}-{}-{}", f.kind, pid, snap.epoch),
                    kind: "kill".into(),
                    pid,
                    start: *start,
                    name: name.clone(),
                    mem_mb: *mem,
                    reason: if ai_hinted && !f.recognized {
                        format!("{} (AI-escalated)", f.title)
                    } else {
                        f.title.clone()
                    },
                    source: if ai_hinted && !f.recognized {
                        "ai".into()
                    } else {
                        f.kind.clone()
                    },
                    ts: snap.epoch,
                });
            }
        }
    }
    let live: HashMap<u32, u64> = snap.procs.iter().map(|p| (p.pid, p.start)).collect();
    actions::merge_new(proposals, &live);
    let pending = actions::count();

    let rec = RunRecord {
        ts: snap.epoch,
        duration_ms,
        trigger: opts.trigger.clone(),
        total_mb: snap.total_mb,
        ram_before_mb: snap.used_mb,
        ram_before_pct: (snap.used_pct * 10.0).round() / 10.0,
        ram_after_mb: after.1,
        ram_after_pct: (after.2 * 10.0).round() / 10.0,
        reclaimed_mb,
        reduced_pct: (reduced_pct * 100.0).round() / 100.0,
        self_cpu_pct: self_cpu,
        proc_count: snap.procs.len(),
        pending,
        findings: findings.iter().map(finding_rec).collect(),
        actions: opt.actions.clone(),
        ai: ai_rec,
        strategies,
    };
    runlog::append(&rec, cfg.schedule.keep_runs);
    rec
}

fn finding_rec(f: &Finding) -> FindingRec {
    FindingRec {
        kind: f.kind.clone(),
        severity: f.severity,
        title: f.title.clone(),
        detail: f.detail.clone(),
        recognized: f.recognized,
    }
}
