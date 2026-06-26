//! Structured per-run records. Each monitoring pass appends ONE compact JSON
//! line to `~/.ram-optimizer/runs.jsonl`: timing, RAM before/after, reclaimed MB,
//! the findings, the optimizer actions, and (if it ran) the AI escalation and
//! any new strategies written to the vector DB.
//!
//! This file is what the web dashboard reads. The UI never scans processes
//! live — it just renders these records — so viewing the dashboard costs almost
//! nothing, which matters for a tool whose whole job is to save RAM.
use crate::config::{state_dir, Config};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct FindingRec {
    pub kind: String,
    pub severity: u8,
    pub title: String,
    pub detail: String,
    /// `false` == AI-escalation candidate (novel/abnormal).
    pub recognized: bool,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct AiRec {
    pub provider: String,
    pub model: String,
    /// The exact prompt sent to the model (so the action log shows what was asked).
    pub prompt: String,
    pub prompt_chars: usize,
    pub advice: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct StrategyRec {
    /// Vector-DB record id.
    pub id: String,
    /// The text embedded as the strategy/incident memory.
    pub text: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct RunRecord {
    pub ts: u64,
    pub duration_ms: u64,
    /// "scheduled" | "manual" | "manual-dry" | "manual-ai"
    pub trigger: String,
    pub total_mb: u64,
    pub ram_before_mb: u64,
    pub ram_before_pct: f64,
    pub ram_after_mb: u64,
    pub ram_after_pct: f64,
    /// Approx MB reclaimed by kill/restart actions this run.
    pub reclaimed_mb: u64,
    /// reclaimed_mb as a percent of total RAM — the per-run effectiveness number.
    pub reduced_pct: f64,
    /// CPU% ram-optimizer itself used during the pass (cost of running the optimizer).
    pub self_cpu_pct: f64,
    pub proc_count: usize,
    /// Confirm-to-act proposals awaiting the user after this run.
    pub pending: usize,
    pub findings: Vec<FindingRec>,
    pub actions: Vec<String>,
    pub ai: Option<AiRec>,
    pub strategies: Vec<StrategyRec>,
}

fn runs_path() -> PathBuf {
    state_dir().join("runs.jsonl")
}

/// Maximum runs shown in the UI action-log and returned by [`recent`] for display.
pub const DISPLAY_RUNS: usize = 20;

/// Append one record using O(1) append I/O; rewrite to trim only when the file
/// has grown more than 10 lines past `keep`, amortising the rewrite cost.
pub fn append(rec: &RunRecord, keep: usize) {
    use std::io::Write as _;
    let path = runs_path();
    let line = match serde_json::to_string(rec) {
        Ok(s) => s,
        Err(_) => return,
    };
    // Fast path: just append the new line.
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{}", line);
    }
    // Slow path: only trim when clearly over the limit (amortises rewrite cost).
    let keep = keep.max(1);
    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return,
    };
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() > keep + 10 {
        let start = lines.len() - keep;
        let _ = std::fs::write(&path, lines[start..].join("\n") + "\n");
    }
}

/// The most recent `n` records, oldest-first.
pub fn recent(n: usize) -> Vec<RunRecord> {
    let s = match std::fs::read_to_string(runs_path()) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let all: Vec<&str> = s.lines().collect();
    let start = all.len().saturating_sub(n);
    all[start..]
        .iter()
        .filter_map(|l| serde_json::from_str::<RunRecord>(l).ok())
        .collect()
}

/// Aggregate effectiveness across the most recent `n` runs (for the metrics view).
pub fn summary(cfg: &Config) -> serde_json::Value {
    let runs = recent(cfg.schedule.keep_runs.min(1000));
    let n = runs.len();
    if n == 0 {
        return serde_json::json!({ "runs": 0 });
    }
    let total_reclaimed: u64 = runs.iter().map(|r| r.reclaimed_mb).sum();
    let acted = runs.iter().filter(|r| r.reclaimed_mb > 0).count();
    let avg_dur: f64 = runs.iter().map(|r| r.duration_ms as f64).sum::<f64>() / n as f64;
    let avg_reduced: f64 = if acted > 0 {
        runs.iter()
            .filter(|r| r.reclaimed_mb > 0)
            .map(|r| r.reduced_pct)
            .sum::<f64>()
            / acted as f64
    } else {
        0.0
    };
    let ai_runs = runs.iter().filter(|r| r.ai.is_some()).count();
    let strategies: usize = runs.iter().map(|r| r.strategies.len()).sum();
    serde_json::json!({
        "runs": n,
        "actedRuns": acted,
        "totalReclaimedMB": total_reclaimed,
        "avgDurationMs": (avg_dur).round(),
        "avgReducedPctWhenActed": (avg_reduced * 100.0).round() / 100.0,
        "aiRuns": ai_runs,
        "strategiesSaved": strategies,
    })
}
