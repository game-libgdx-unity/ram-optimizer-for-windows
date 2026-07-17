//! Config loading. Every struct is `#[serde(default)]`, so a config file may
//! specify only the keys it wants to override; the rest fall back to defaults.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub thresholds: Thresholds,
    /// User-defined rules: match an app and alert / kill / restart it.
    pub rules: Vec<Rule>,
    pub ai: Ai,
    pub alerts: Alerts,
    pub vectordb: VectorDb,
    pub optimize: Optimize,
    pub ui: Ui,
    pub schedule: Schedule,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Thresholds {
    #[serde(rename = "highRamMB")]
    pub high_ram_mb: u64,
    pub single_proc_ram_pct: f64,
    pub high_cpu_pct: f64,
    pub cpu_rise_pct: f64,
    pub dup_count: usize,
    /// Min same-named processes with a dead parent to flag an orphan pileup.
    pub orphan_count: usize,
    /// Min RAM growth (MB) run-over-run on a sizeable process to flag a leak.
    #[serde(rename = "memRiseMB")]
    pub mem_rise_mb: u64,
    pub system_ram_pct_alert: f64,
    pub ignore_names: Vec<String>,
}
impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            high_ram_mb: 1500,
            single_proc_ram_pct: 25.0,
            high_cpu_pct: 80.0,
            cpu_rise_pct: 40.0,
            dup_count: 10,
            orphan_count: 5,
            mem_rise_mb: 400,
            system_ram_pct_alert: 90.0,
            ignore_names: [
                // common OS/browser/idle processes you usually don't want flagged
                "svchost.exe",
                "explorer.exe",
                "dwm.exe",
                "conhost.exe",
                "MsMpEng.exe",
                "chrome.exe",
                "msedge.exe",
                "firefox",
                "Google Chrome",
                "WindowServer",
                "kernel_task",
                "System Idle Process",
                "System",
                "Memory Compression",
                "Registry",
                "Idle",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

/// A user rule: match one or more processes, and (optionally) act on them.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Rule {
    pub name: String,
    #[serde(rename = "match")]
    pub match_: Match,
    /// Fire if a matching process (or, with `group`, the matched total) uses ≥ this many MB.
    #[serde(rename = "whenProcRamMB")]
    pub when_proc_ram_mb: Option<u64>,
    /// ...or if a matching process is ≥ this CPU%.
    pub when_proc_cpu_pct: Option<f64>,
    /// Only act when overall system RAM is ≥ this percent (0 = any).
    pub when_system_ram_pct: f64,
    /// `alert` (notify only) | `kill` | `restart`.
    pub action: String,
    /// For `action: "restart"` — the command (argv) to launch after killing.
    pub restart_command: Vec<String>,
    /// When acting on several matches, always spare the most-recently-started one.
    pub spare_newest: bool,
    /// Treat the matched set as a group: the RAM threshold applies to their sum,
    /// and the action hits all of them.
    pub group: bool,
}
impl Default for Rule {
    fn default() -> Self {
        Rule {
            name: String::new(),
            match_: Match::default(),
            when_proc_ram_mb: None,
            when_proc_cpu_pct: None,
            when_system_ram_pct: 0.0,
            action: "alert".into(),
            restart_command: Vec::new(),
            spare_newest: false,
            group: false,
        }
    }
}

/// Match conditions (case-insensitive). All provided sub-conditions must hold.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct Match {
    /// Exact process name, e.g. "chrome.exe".
    pub name: Option<String>,
    /// Substring of the executable path, e.g. "AppData\\Local\\MyApp".
    pub path_contains: Option<String>,
    /// Substring of the full command line, e.g. "--my-flag".
    pub cmd_contains: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Ai {
    pub enabled: bool,
    pub provider: String,
    pub fallback: Vec<String>,
    pub min_minutes_between_escalations: u64,
    pub groq_api_key: String,
    pub groq_model: String,
    pub openai_api_key: String,
    pub openai_model: String,
}
impl Default for Ai {
    fn default() -> Self {
        Ai {
            enabled: false,
            provider: "openai".into(),
            fallback: vec![],
            min_minutes_between_escalations: 60,
            groq_api_key: String::new(),
            groq_model: "llama-3.3-70b-versatile".into(),
            openai_api_key: String::new(),
            openai_model: "gpt-4o-mini".into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Alerts {
    pub toast: bool,
    pub log: bool,
    pub cooldown_minutes: u64,
    /// When true, OS toast notifications are suppressed unless overall system RAM
    /// is at/above `thresholds.systemRamPctAlert` — so you're only nagged when the
    /// machine is actually under memory pressure (the non-aggressive band), not for
    /// every per-process / CPU / antimalware finding while RAM is fine. Findings are
    /// still recorded to the log + dashboard; only the popup is gated. Default false.
    pub only_under_ram_pressure: bool,
}
impl Default for Alerts {
    fn default() -> Self {
        Alerts {
            toast: true,
            log: true,
            cooldown_minutes: 30,
            only_under_ram_pressure: false,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct VectorDb {
    pub enabled: bool,
    pub provider: String,
    pub url: String,
    pub token: String,
    pub top_k: usize,
}
impl Default for VectorDb {
    fn default() -> Self {
        VectorDb {
            enabled: false,
            provider: "upstash".into(),
            url: String::new(),
            token: String::new(),
            top_k: 3,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Optimize {
    /// Master switch for kill/restart rule actions. When false, rules with those
    /// actions are downgraded to alerts (nothing is killed).
    pub enabled: bool,
    /// Aggressive tier: at/above this system-RAM%, the optimizer auto-kills the
    /// largest eligible process(es) to reclaim memory WITHOUT confirmation — even
    /// with no matching rule. `0` disables it (default). Eligibility skips
    /// `thresholds.ignoreNames` (your safety lever — browsers/OS processes are
    /// ignored by default), the antimalware service, and RAM Optimizer itself, and only
    /// considers processes ≥ ~300 MB. The gentler tier (alerts + confirm-to-act
    /// proposals) is governed by `thresholds.systemRamPctAlert`, which should be
    /// the lower number. See `optimize::auto_relief`.
    pub auto_act_system_ram_pct: f64,
    /// Max processes the aggressive tier may kill in one pass (default 1).
    pub auto_act_max_kills: usize,
    /// Hysteresis for the aggressive tier: how many *consecutive* passes system
    /// RAM must stay at/above `autoActSystemRamPct` before the no-confirmation
    /// kill fires. `2` (default) means "wait one extra pass" — e.g. with a 5-min
    /// schedule the kill only happens after RAM has been critical for ~10 min, so
    /// a momentary spike is ignored. `1` (or `0`) = act on the first critical pass
    /// (the old behavior). Does not affect the reap tier. See `optimize::run`.
    pub auto_act_confirm_passes: usize,
    /// Non-aggressive tier: at/above this system-RAM%, auto-reap duplicate / orphan
    /// / spam process pileups (newest spared). `0` disables (default). Meant to sit
    /// *below* `autoActSystemRamPct`.
    pub auto_reap_system_ram_pct: f64,
    /// Min instances of one name to reap in the non-aggressive band (RAM between
    /// the reap and aggressive thresholds). Applies to both duplicates and orphans.
    pub auto_reap_count: usize,
    /// Min instances to reap once RAM reaches the aggressive threshold — lower, so
    /// critical RAM reaps smaller pileups too. Both duplicates and orphans.
    pub auto_reap_count_aggressive: usize,
    /// Process names (case-insensitive) the **reap tier** must never touch, even
    /// though they're not on `thresholds.ignoreNames`. Use this for legitimate
    /// **multi-process apps** — browsers (`chrome.exe`, `msedge.exe`,
    /// `msedgewebview2.exe`), Electron apps, etc. — whose many same-named processes
    /// are normal architecture, NOT a leaked/duplicate pileup. Reaping them kills
    /// the main process (reap spares the *newest*, i.e. a child) and closes the
    /// app, and reap never relaunches what it prunes. The aggressive **relief**
    /// tier can still target these (so they stay reclaimable under critical RAM);
    /// this only stops the duplicate-pileup reaper from shredding them. Empty by
    /// default. See `detect::reap_targets`.
    pub no_reap_names: Vec<String>,
    /// Process names (case-insensitive) to **kill on sight every pass** — a soft
    /// "block". RAM Optimizer can't truly stop an app from launching without admin OS
    /// policies (Image File Execution Options, ACL deny-execute, AppLocker — see
    /// README), so instead it terminates any matching process on every run,
    /// regardless of RAM. This is the opposite of a guard: it bypasses
    /// `ignoreNames`/`noReapNames` and never relaunches. It still spares the
    /// OS-critical floor and RAM Optimizer itself (so a typo can't brick the machine).
    /// Empty (default) = nothing blocked. See `optimize::run_blocklist`.
    pub block_names: Vec<String>,
    /// Process names (case-insensitive) to relaunch after the aggressive tier kills
    /// them — e.g. `["claude.exe","node.exe","java.exe"]`. Relaunched with their
    /// captured argv + working dir. Empty (default) = never restart.
    pub restart_after_kill: Vec<String>,
    /// Guard Claude — keep it alive across the optimizer's automatic kills.
    /// Default true. Two effects:
    ///   * **Protect**: Claude's live process tree (every Claude instance plus its
    ///     live ancestors/descendants) is never chosen as an aggressive-relief
    ///     kill target, so a pass kills other hogs (e.g. Chrome) first and keeps
    ///     Claude up as long as possible.
    ///   * **Relaunch**: if a reap/relief kill still takes Claude's tree down,
    ///     re-check right after the kills whether any Claude is alive and, if not,
    ///     relaunch it from its captured argv + working dir.
    ///
    /// Identifies Claude via `claudeMarkers`. See `crate::guard`.
    pub guard_claude: bool,
    /// Case-insensitive markers identifying a Claude process, matched against the
    /// process name AND its command line / exe path — so both the native
    /// `claude.exe` and a `node.exe` running Claude Code are recognized. Default
    /// `["claude"]`; empty disables the guard.
    pub claude_markers: Vec<String>,
    /// Opt-in (default false): when the machine is under RAM pressure AND the
    /// Windows antimalware service (Microsoft Defender / MsMpEng) is running hot
    /// AND Defender confirms there are no active threats, stop that service to
    /// reclaim resources. This WEAKENS antivirus protection, so it is off by
    /// default and only ever acts on a confirmed "no active threats" signal. See
    /// `windefend` + `optimize::tame_antimalware`. (Windows-only; no-op elsewhere.)
    pub pause_antimalware_when_idle: bool,
    /// RAM footprint (MB) at/above which the antimalware service counts as "hot
    /// enough to tame" once `pauseAntimalwareWhenIdle` is on and the machine is
    /// under RAM pressure with no active threats. `0` (default) keeps the original
    /// conservative behavior of `2 × highRamMB`. Lower it (e.g. `250`) to reclaim
    /// Defender's RAM even when it's only modestly resident — it still only acts
    /// under RAM pressure and never when threats are present. See
    /// `optimize::tame_antimalware`.
    pub antimalware_hot_ram_mb: u64,
    /// System-RAM% at/above which the antimalware service may be tamed (see
    /// `pauseAntimalwareWhenIdle`). This is the **non-aggressive** band: it is
    /// independent of `autoActSystemRamPct`/its hysteresis, so Defender can be
    /// paused at the gentler threshold (e.g. 85%) without waiting for the
    /// aggressive tier. `0` (default) falls back to `thresholds.systemRamPctAlert`.
    /// See `optimize::tame_antimalware`.
    pub antimalware_pause_system_ram_pct: f64,
}
impl Default for Optimize {
    fn default() -> Self {
        Optimize {
            enabled: true,
            auto_act_system_ram_pct: 0.0,
            auto_act_max_kills: 1,
            auto_act_confirm_passes: 2,
            auto_reap_system_ram_pct: 0.0,
            auto_reap_count: 10,
            auto_reap_count_aggressive: 5,
            no_reap_names: Vec::new(),
            block_names: Vec::new(),
            restart_after_kill: Vec::new(),
            guard_claude: true,
            claude_markers: vec!["claude".into()],
            pause_antimalware_when_idle: false,
            antimalware_hot_ram_mb: 0,
            antimalware_pause_system_ram_pct: 0.0,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Ui {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
    /// When true, launching the dashboard (double-click / bare `ram-optimizer`) starts
    /// it hidden in the tray instead of showing the window — so it never auto-pops
    /// while the background monitor is doing the work. `ram-optimizer ui` still forces
    /// the window open; `--tray` always starts hidden regardless of this flag.
    pub start_hidden: bool,
}
impl Default for Ui {
    fn default() -> Self {
        Ui {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 8787,
            start_hidden: false,
        }
    }
}

/// How often the OS scheduler runs RAM Optimizer, controllable from the dashboard.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Schedule {
    /// Minutes between scheduled passes (1–1440).
    pub interval_minutes: u64,
    /// OS task/agent name (Windows Task Scheduler / launchd label / cron marker).
    pub task_name: String,
    /// How many run records to retain in ~/.ram-optimizer/runs.jsonl.
    pub keep_runs: usize,
}
impl Default for Schedule {
    fn default() -> Self {
        Schedule {
            interval_minutes: 5,
            task_name: "RamOptimizer".into(),
            keep_runs: 100,
        }
    }
}

fn candidate_paths() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        v.push(cwd.join("config.json"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            v.push(dir.join("config.json"));
            if let Some(up2) = dir.parent().and_then(|p| p.parent()) {
                v.push(up2.join("config.json"));
            }
        }
    }
    if let Some(home) = dirs::home_dir() {
        v.push(home.join(".config").join("ram-optimizer").join("config.json"));
    }
    v
}

/// Where the UI writes config edits: the first existing candidate, else cwd/config.json.
pub fn config_write_path() -> PathBuf {
    for f in candidate_paths() {
        if f.exists() {
            return f;
        }
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("config.json")
}

pub fn load_config() -> Config {
    for f in candidate_paths() {
        match std::fs::read_to_string(&f) {
            Ok(text) => match serde_json::from_str::<Config>(&text) {
                Ok(c) => return c,
                Err(e) => eprintln!("[ram-optimizer] bad config {}: {}", f.display(), e),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!("[ram-optimizer] cannot read {}: {}", f.display(), e),
        }
    }
    Config::default()
}

/// Per-user state dir (~/.ram-optimizer), created if missing.
pub fn state_dir() -> PathBuf {
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ram-optimizer");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Deep-merge a partial `patch` into config.json, validate it parses as a
/// `Config`, then write it back pretty-printed. Used by the dashboard's
/// Settings + Schedule tabs. Returns the path written, or an error string.
pub fn save_patch(patch: serde_json::Value) -> Result<String, String> {
    let path = config_write_path();
    let mut existing: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    deep_merge(&mut existing, patch);
    serde_json::from_value::<Config>(existing.clone())
        .map_err(|e| format!("config invalid: {e}"))?;
    let pretty = serde_json::to_string_pretty(&existing).unwrap_or_else(|_| existing.to_string());
    std::fs::write(&path, pretty).map_err(|e| format!("write failed: {e}"))?;
    Ok(path.display().to_string())
}

fn deep_merge(a: &mut serde_json::Value, b: serde_json::Value) {
    match b {
        serde_json::Value::Object(bm) => {
            if !a.is_object() {
                *a = serde_json::Value::Object(serde_json::Map::new());
            }
            let am = a.as_object_mut().unwrap();
            for (k, bv) in bm {
                deep_merge(am.entry(k).or_insert(serde_json::Value::Null), bv);
            }
        }
        other => *a = other,
    }
}
