//! Native desktop dashboard (egui/eframe). It is a *viewer + controller*, not a
//! monitor: it reads the records previous scheduled runs wrote to
//! `~/.ram-optimizer/runs.jsonl` (+ the last process snapshot and the log) and renders
//! them. It never scans processes on its own except when YOU press "Run now".
//!
//! The optimizer itself runs from the OS scheduler in the background and is
//! completely independent of this window: closing the app (or quitting from the
//! tray) does NOT stop the schedule — only the Schedule tab's Stop button does.
use crate::config::{self, Config};
use crate::pass::{self, PassOpts};
use crate::runlog::{self, AiRec, RunRecord};
use crate::tray::{self, TrayAction};
use crate::util::now_epoch;
use crate::{actions, collect, scheduler, state, vectordb};
use eframe::egui;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

const RELOAD_SECS: u64 = 4;

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Overview,
    Pending,
    Metrics,
    ActionLog,
    Settings,
    Schedule,
}

enum BgMsg {
    Pass(Box<RunRecord>),
    Sched(Result<String, String>),
    /// One-time startup job: ensure the schedule is running, plus an initial pass.
    Startup {
        sched: Result<String, String>,
        rec: Box<RunRecord>,
    },
}

/// Editable mirror of config.json for the Settings tab.
#[derive(Default)]
struct Form {
    optimize_enabled: bool,
    ai_enabled: bool,
    ai_provider: String,
    vdb_enabled: bool,
    vdb_url: String,
    openai_key: String,
    groq_key: String,
    vdb_token: String,
    openai_set: bool,
    groq_set: bool,
    vdb_token_set: bool,
    sys_ram_pct: f64,
    auto_act_pct: f64,
    auto_act_confirm_passes: usize,
    high_ram_mb: u64,
    high_cpu_pct: f64,
    single_proc_pct: f64,
    dup_count: usize,
    ignore_names: String,
    rules_json: String,
    alerts_toast: bool,
    ui_start_hidden: bool,
    pause_antimalware_when_idle: bool,
}

pub struct RamOptimizerApp {
    cfg: Config,
    tab: Tab,
    tray: Option<tray::Tray>,
    really_quit: bool,

    runs: Vec<RunRecord>,
    pending: Vec<actions::Proposal>,
    snapshot: Option<collect::Snapshot>,
    log: Vec<String>,
    sched: scheduler::SchedStatus,
    summary: serde_json::Value,
    vdb_enabled: bool,
    vdb_default: bool,
    last_reload: Instant,

    proc_filter: String,
    sched_interval: u64,

    rx: Option<mpsc::Receiver<BgMsg>>,
    busy: Option<String>,
    status_msg: String,
    status_err: bool,
    /// Drives the one-time "auto-start the server" job on the first frame.
    startup_done: bool,
    /// Launched with `--tray` (window starts invisible, managed from the tray).
    start_hidden: bool,
    /// While set (a safety timeout), poll each frame and natively hide the window
    /// the first time it appears — eframe shows the root window after first paint
    /// and ignores Visible(false), so this realises `--tray` startup.
    hide_until: Option<Instant>,
    /// Set by the background tray thread when "Run now" is clicked; consumed in
    /// `update`. Tray clicks are handled off the UI loop because eframe stops
    /// calling `update` while the window is hidden in the tray.
    run_now: Arc<AtomicBool>,
    /// Whether the background tray-event thread has been spawned.
    tray_thread: bool,

    form: Form,
    show_ai: bool,
    ai_rec: Option<AiRec>,
}

/// Entry point for `ram-optimizer ui`. When `start_hidden` is set (the `--tray` /
/// launch-at-login path) the window opens invisible — only the tray icon shows —
/// and the background schedule + initial scan still run; the user opens the
/// window from the tray's "Open RAM Optimizer".
pub fn run(start_hidden: bool) {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 720.0])
            .with_min_inner_size([720.0, 460.0])
            .with_visible(!start_hidden)
            .with_title("RAM Optimizer"),
        ..Default::default()
    };
    if let Err(e) = eframe::run_native(
        "RAM Optimizer",
        options,
        Box::new(move |cc| Box::new(RamOptimizerApp::new(cc, start_hidden))),
    ) {
        eprintln!("[ram-optimizer ui] {e}");
    }
}

fn read_log_tail(n: usize) -> Vec<String> {
    let p = config::state_dir().join("ram-optimizer.log");
    match std::fs::read_to_string(p) {
        Ok(s) => {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(n);
            lines[start..].iter().map(|l| l.to_string()).collect()
        }
        Err(_) => vec![],
    }
}

/// Top-bar badge for the background schedule: (text, colour). Green when the OS
/// task is installed + enabled, amber when installed-but-stopped, red when absent.
fn monitor_badge(s: &scheduler::SchedStatus) -> (&'static str, egui::Color32) {
    if s.installed && s.enabled {
        (
            "Background monitor: running ✓",
            egui::Color32::from_rgb(63, 185, 80),
        )
    } else if s.installed {
        (
            "Background monitor: stopped",
            egui::Color32::from_rgb(210, 153, 34),
        )
    } else {
        (
            "Background monitor: not installed",
            egui::Color32::from_rgb(248, 81, 73),
        )
    }
}

fn ago(ts: u64) -> String {
    if ts == 0 {
        return "never".into();
    }
    let now = now_epoch();
    let d = now.saturating_sub(ts);
    if d < 60 {
        format!("{d}s ago")
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86400)
    }
}

/// Natively hide every visible top-level window owned by this process. Needed for
/// `--tray` startup and close-to-tray because eframe shows the root window after
/// its first paint and ignores `Visible(false)` on it. No-op off Windows.
#[cfg(windows)]
static HID_ANY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Returns true if it hid at least one (previously visible) window — lets the
/// caller poll until the window has actually appeared, hiding it on the first
/// frame it's shown (so the `--tray` startup flash is ~one frame).
#[cfg(windows)]
fn hide_own_windows() -> bool {
    use std::ffi::c_void;
    use std::sync::atomic::Ordering;
    type Hwnd = *mut c_void;
    const SW_HIDE: i32 = 0;
    extern "system" {
        fn EnumWindows(cb: extern "system" fn(Hwnd, isize) -> i32, l: isize) -> i32;
        fn GetWindowThreadProcessId(h: Hwnd, pid: *mut u32) -> u32;
        fn IsWindowVisible(h: Hwnd) -> i32;
        fn ShowWindow(h: Hwnd, cmd: i32) -> i32;
    }
    extern "system" fn cb(h: Hwnd, _l: isize) -> i32 {
        unsafe {
            let mut pid = 0u32;
            GetWindowThreadProcessId(h, &mut pid);
            if pid == std::process::id() && IsWindowVisible(h) != 0 {
                ShowWindow(h, SW_HIDE);
                HID_ANY.store(true, Ordering::Relaxed);
            }
        }
        1 // keep enumerating
    }
    HID_ANY.store(false, Ordering::Relaxed);
    unsafe { EnumWindows(cb, 0) };
    HID_ANY.load(Ordering::Relaxed)
}

/// Natively show + foreground this process's main window (counterpart to
/// [`hide_own_windows`], for "Open" from the tray). No-op off Windows.
#[cfg(windows)]
fn show_own_windows() {
    use std::ffi::c_void;
    type Hwnd = *mut c_void;
    const SW_SHOW: i32 = 5;
    extern "system" {
        fn EnumWindows(cb: extern "system" fn(Hwnd, isize) -> i32, l: isize) -> i32;
        fn GetWindowThreadProcessId(h: Hwnd, pid: *mut u32) -> u32;
        fn ShowWindow(h: Hwnd, cmd: i32) -> i32;
        fn SetForegroundWindow(h: Hwnd) -> i32;
    }
    extern "system" fn cb(h: Hwnd, _l: isize) -> i32 {
        unsafe {
            let mut pid = 0u32;
            GetWindowThreadProcessId(h, &mut pid);
            if pid == std::process::id() {
                ShowWindow(h, SW_SHOW);
                SetForegroundWindow(h);
            }
        }
        1
    }
    unsafe { EnumWindows(cb, 0) };
}

#[cfg(not(windows))]
fn hide_own_windows() -> bool {
    false
}
#[cfg(not(windows))]
fn show_own_windows() {}

impl RamOptimizerApp {
    fn new(cc: &eframe::CreationContext<'_>, start_hidden: bool) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let cfg = config::load_config();
        let sched_interval = cfg.schedule.interval_minutes;
        // Optional startup tab (used for documentation screenshots).
        let tab = match std::env::var("RAM_OPTIMIZER_UI_TAB")
            .unwrap_or_default()
            .as_str()
        {
            "pending" => Tab::Pending,
            "metrics" => Tab::Metrics,
            "actionlog" | "log" => Tab::ActionLog,
            "settings" => Tab::Settings,
            "schedule" => Tab::Schedule,
            _ => Tab::Overview,
        };
        let mut app = RamOptimizerApp {
            cfg,
            tab,
            tray: tray::Tray::new(),
            really_quit: false,
            runs: vec![],
            pending: vec![],
            snapshot: None,
            log: vec![],
            sched: scheduler::SchedStatus::default(),
            summary: serde_json::json!({ "runs": 0 }),
            vdb_enabled: false,
            vdb_default: false,
            last_reload: Instant::now(),
            proc_filter: String::new(),
            sched_interval,
            rx: None,
            busy: None,
            status_msg: String::new(),
            status_err: false,
            startup_done: false,
            start_hidden,
            hide_until: None,
            run_now: Arc::new(AtomicBool::new(false)),
            tray_thread: false,
            form: Form::default(),
            show_ai: false,
            ai_rec: None,
        };
        app.reload();
        app.load_form();
        app
    }

    /// Re-read the log files (cheap; no process scan). Does NOT touch the
    /// Settings form, so editing is never clobbered.
    fn reload(&mut self) {
        self.runs = runlog::recent(runlog::DISPLAY_RUNS);
        self.pending = actions::load();
        self.snapshot = state::load_prev();
        self.log = read_log_tail(runlog::DISPLAY_RUNS);
        self.sched = scheduler::status(&self.cfg);
        self.summary = runlog::summary(&self.cfg);
        self.vdb_enabled = vectordb::enabled(&self.cfg);
        self.vdb_default = vectordb::using_builtin_default(&self.cfg);
        self.last_reload = Instant::now();
    }

    fn load_form(&mut self) {
        let c = &self.cfg;
        self.form = Form {
            optimize_enabled: c.optimize.enabled,
            ai_enabled: c.ai.enabled,
            ai_provider: c.ai.provider.clone(),
            vdb_enabled: c.vectordb.enabled,
            vdb_url: c.vectordb.url.clone(),
            openai_key: String::new(),
            groq_key: String::new(),
            vdb_token: String::new(),
            openai_set: !c.ai.openai_api_key.is_empty(),
            groq_set: !c.ai.groq_api_key.is_empty(),
            vdb_token_set: !c.vectordb.token.is_empty(),
            sys_ram_pct: c.thresholds.system_ram_pct_alert,
            auto_act_pct: c.optimize.auto_act_system_ram_pct,
            auto_act_confirm_passes: c.optimize.auto_act_confirm_passes,
            high_ram_mb: c.thresholds.high_ram_mb,
            high_cpu_pct: c.thresholds.high_cpu_pct,
            single_proc_pct: c.thresholds.single_proc_ram_pct,
            dup_count: c.thresholds.dup_count,
            ignore_names: c.thresholds.ignore_names.join("\n"),
            rules_json: serde_json::to_string_pretty(&c.rules).unwrap_or_else(|_| "[]".into()),
            alerts_toast: c.alerts.toast,
            ui_start_hidden: c.ui.start_hidden,
            pause_antimalware_when_idle: c.optimize.pause_antimalware_when_idle,
        };
    }

    fn latest(&self) -> Option<&RunRecord> {
        self.runs.last()
    }

    fn start_pass(&mut self, ctx: &egui::Context, opts: PassOpts, label: &str) {
        if self.busy.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let cfg = self.cfg.clone();
        self.rx = Some(rx);
        self.busy = Some(label.to_string());
        std::thread::spawn(move || {
            let rec = pass::run_pass(&cfg, &opts);
            let _ = tx.send(BgMsg::Pass(Box::new(rec)));
        });
        ctx.request_repaint();
    }

    fn start_sched(
        &mut self,
        ctx: &egui::Context,
        start: bool,
        interval: Option<u64>,
        label: &str,
    ) {
        if self.busy.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let cfg = self.cfg.clone();
        self.rx = Some(rx);
        self.busy = Some(label.to_string());
        std::thread::spawn(move || {
            let res = if let Some(min) = interval {
                let _ = config::save_patch(serde_json::json!({
                    "schedule": { "intervalMinutes": min }
                }));
                scheduler::set_interval(&cfg, min)
            } else if start {
                scheduler::set_enabled(&cfg, true)
            } else {
                scheduler::set_enabled(&cfg, false)
            };
            let _ = tx.send(BgMsg::Sched(res));
        });
        ctx.request_repaint();
    }

    /// One-time on-open job (the "auto run the server" part): make sure the OS
    /// schedule is installed + enabled, then run one monitor-only pass so the
    /// dashboard shows fresh data immediately. Runs off-thread so the window
    /// paints right away.
    fn start_startup(&mut self, ctx: &egui::Context) {
        if self.busy.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let cfg = self.cfg.clone();
        self.rx = Some(rx);
        self.busy = Some("Starting background monitor…".into());
        std::thread::spawn(move || {
            let sched = scheduler::autostart(&cfg);
            let rec = pass::run_pass(
                &cfg,
                &PassOpts {
                    act: false,
                    escalate: false,
                    force_ai: false,
                    alert: false,
                    trigger: "startup".into(),
                },
            );
            let _ = tx.send(BgMsg::Startup {
                sched,
                rec: Box::new(rec),
            });
        });
        ctx.request_repaint();
    }

    fn start_approve(&mut self, ctx: &egui::Context, id: String) {
        if self.busy.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.busy = Some("Executing approved action…".into());
        std::thread::spawn(move || {
            let _ = tx.send(BgMsg::Sched(actions::approve(&id)));
        });
        ctx.request_repaint();
    }

    /// Approve + kill every queued proposal for one process name (the grouped
    /// "Approve & kill all" button). Runs off-thread like `start_approve`.
    fn start_approve_group(&mut self, ctx: &egui::Context, name: String) {
        if self.busy.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.busy = Some(format!("Killing all {name}…"));
        std::thread::spawn(move || {
            let _ = tx.send(BgMsg::Sched(actions::approve_group(&name)));
        });
        ctx.request_repaint();
    }

    /// Add `name` to `optimize.blockNames` (persisted), then kill its running
    /// instances now. Future passes auto-kill it on sight (soft block). Backs the
    /// Pending tab's "Block" button.
    fn block_and_kill(&mut self, ctx: &egui::Context, name: String) {
        if self.busy.is_some() {
            return;
        }
        let mut names = self.cfg.optimize.block_names.clone();
        if !names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
            names.push(name.clone());
        }
        match config::save_patch(serde_json::json!({ "optimize": { "blockNames": names } })) {
            Ok(_) => self.cfg = config::load_config(),
            Err(e) => {
                self.status_msg = format!("Couldn't save blocklist: {e}");
                self.status_err = true;
                return;
            }
        }
        self.start_approve_group(ctx, name.clone());
        self.status_msg =
            format!("Blocked {name} — killed now, and auto-killed every future pass.");
        self.status_err = false;
    }

    fn apply_settings(&mut self) {
        let rules: serde_json::Value = match serde_json::from_str(&self.form.rules_json) {
            Ok(v @ serde_json::Value::Array(_)) => v,
            _ => {
                self.status_msg = "Rules must be a valid JSON array.".into();
                self.status_err = true;
                return;
            }
        };
        let ignore: Vec<String> = self
            .form
            .ignore_names
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let mut patch = serde_json::json!({
            "optimize": {
                "enabled": self.form.optimize_enabled,
                "autoActSystemRamPct": self.form.auto_act_pct,
                "autoActConfirmPasses": self.form.auto_act_confirm_passes,
                "pauseAntimalwareWhenIdle": self.form.pause_antimalware_when_idle,
            },
            "ai": { "enabled": self.form.ai_enabled, "provider": self.form.ai_provider },
            "vectordb": { "enabled": self.form.vdb_enabled, "url": self.form.vdb_url.trim() },
            "alerts": { "toast": self.form.alerts_toast },
            "ui": { "startHidden": self.form.ui_start_hidden },
            "thresholds": {
                "systemRamPctAlert": self.form.sys_ram_pct,
                "highRamMB": self.form.high_ram_mb,
                "highCpuPct": self.form.high_cpu_pct,
                "singleProcRamPct": self.form.single_proc_pct,
                "dupCount": self.form.dup_count,
                "ignoreNames": ignore,
            },
            "rules": rules,
        });
        // Only write secrets the user actually typed (blank keeps existing).
        if !self.form.openai_key.trim().is_empty() {
            patch["ai"]["openaiApiKey"] = serde_json::json!(self.form.openai_key.trim());
        }
        if !self.form.groq_key.trim().is_empty() {
            patch["ai"]["groqApiKey"] = serde_json::json!(self.form.groq_key.trim());
        }
        if !self.form.vdb_token.trim().is_empty() {
            patch["vectordb"]["token"] = serde_json::json!(self.form.vdb_token.trim());
        }
        match config::save_patch(patch) {
            Ok(path) => {
                self.status_msg = format!("Saved to {path}");
                self.status_err = false;
                self.cfg = config::load_config();
                self.reload();
                self.load_form();
            }
            Err(e) => {
                self.status_msg = e;
                self.status_err = true;
            }
        }
    }

    fn handle_bg(&mut self, ctx: &egui::Context) {
        let msg = match &self.rx {
            Some(rx) => match rx.try_recv() {
                Ok(m) => Some(m),
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(150));
                    return;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.rx = None;
                    self.busy = None;
                    return;
                }
            },
            None => return,
        };
        self.rx = None;
        self.busy = None;
        match msg.unwrap() {
            BgMsg::Pass(rec) => {
                self.status_msg = format!(
                    "Pass done in {} ms — {} finding(s), reclaimed {} MB ({:.2}%).",
                    rec.duration_ms,
                    rec.findings.len(),
                    rec.reclaimed_mb,
                    rec.reduced_pct
                );
                self.status_err = false;
                if let Some(ai) = &rec.ai {
                    self.ai_rec = Some(ai.clone());
                    self.show_ai = true;
                }
            }
            BgMsg::Sched(res) => match res {
                Ok(m) => {
                    self.status_msg = m;
                    self.status_err = false;
                }
                Err(e) => {
                    self.status_msg = format!("Schedule action failed: {e}");
                    self.status_err = true;
                }
            },
            BgMsg::Startup { sched, rec } => {
                let sched_msg = match sched {
                    Ok(m) => m,
                    Err(e) => format!("schedule not started ({e})"),
                };
                self.status_msg = format!(
                    "{sched_msg} · initial scan: {} finding(s) in {} ms.",
                    rec.findings.len(),
                    rec.duration_ms
                );
                self.status_err = false;
            }
        }
        self.cfg = config::load_config();
        self.reload();
    }

    /// Spawn the background thread that handles tray-menu clicks. It must run off
    /// the eframe loop: while the window is hidden in the tray, eframe stops
    /// calling `update`, so a click handled there would never be seen. The thread
    /// natively shows the window (which also un-freezes the loop) and signals
    /// "Run now"/"Quit" back via shared state.
    fn spawn_tray_thread(&mut self, ctx: &egui::Context) {
        if self.tray_thread {
            return;
        }
        let Some(tray) = &self.tray else { return };
        self.tray_thread = true;
        let ids: tray::TrayIds = tray.ids();
        let ctx = ctx.clone();
        let run_now = self.run_now.clone();
        let show = |ctx: &egui::Context| {
            show_own_windows();
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            ctx.request_repaint();
        };
        std::thread::spawn(move || loop {
            // Wakes on a "show" signal (a 2nd launch / external) or every 100ms to
            // poll the tray menu — all off the eframe loop, which is frozen while
            // the window is hidden.
            if crate::single::wait_show(100) {
                show(&ctx);
            }
            while let Some(action) = tray::poll_action(&ids) {
                match action {
                    TrayAction::Open => show(&ctx),
                    TrayAction::RunNow => {
                        show(&ctx);
                        run_now.store(true, Ordering::Relaxed);
                    }
                    // The OS-scheduled monitor is independent of this process, so a
                    // hard exit here is fine and reliably quits even while hidden.
                    TrayAction::Quit => std::process::exit(0),
                }
            }
        });
    }
}

impl eframe::App for RamOptimizerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let ctx = ctx.clone();

        // First frame: kick off the auto-start (ensure the schedule runs) + an
        // initial scan, so opening the app also gets the background monitor going.
        if !self.startup_done {
            self.startup_done = true;
            // `--tray`: keep the window hidden (tray-only). with_visible(false) at
            // creation isn't enough — eframe shows the window after the first paint
            // — so we re-assert "hidden" for the next several frames. If there's no
            // tray to restore it from (e.g. Linux), show it instead of stranding it.
            if self.start_hidden && self.tray.is_some() {
                // eframe ignores Visible(false) on the root viewport here and shows
                // the window after its first paint, so poll until it appears and
                // hide it natively the moment it does. The value is a safety
                // timeout. (No tray ⇒ leave it shown so it isn't stranded, e.g. on
                // Linux.)
                self.hide_until = Some(Instant::now() + Duration::from_millis(3000));
            }
            self.start_startup(&ctx);
            self.spawn_tray_thread(&ctx);
        }
        // Hide the window the first frame it becomes visible (minimises the flash),
        // then sync eframe's logical state. Give up after the safety timeout.
        if let Some(timeout) = self.hide_until {
            if hide_own_windows() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                self.hide_until = None;
            } else if Instant::now() >= timeout {
                self.hide_until = None;
            } else {
                ctx.request_repaint_after(Duration::from_millis(16));
            }
        }

        self.handle_bg(&ctx);
        // "Run now" requested from the tray thread.
        if self.run_now.swap(false, Ordering::Relaxed) {
            self.start_pass(
                &ctx,
                PassOpts {
                    act: true,
                    escalate: false,
                    force_ai: false,
                    alert: true,
                    trigger: "manual".into(),
                },
                "Running optimization…",
            );
        }

        // Close-to-tray: the window X hides the app instead of exiting, so the
        // tray (and the background schedule) keep running.
        if ctx.input(|i| i.viewport().close_requested()) && self.tray.is_some() && !self.really_quit
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            hide_own_windows();
            self.status_msg =
                "Minimized to tray — background schedule still running. Tray ▸ Quit to exit."
                    .into();
            self.status_err = false;
        }

        // Periodically re-read the log files (cheap). Never overwrites the form.
        if self.last_reload.elapsed() > Duration::from_secs(RELOAD_SECS) {
            self.cfg = config::load_config();
            self.reload();
        }

        self.top_bar(&ctx);
        let ctx2 = ctx.clone();
        egui::CentralPanel::default().show(&ctx, |ui| match self.tab {
            Tab::Overview => self.tab_overview(ui, &ctx2),
            Tab::Pending => self.tab_pending(ui, &ctx2),
            Tab::Metrics => self.tab_metrics(ui),
            Tab::ActionLog => self.tab_action_log(ui),
            Tab::Settings => self.tab_settings(ui),
            Tab::Schedule => self.tab_schedule(ui, &ctx2),
        });

        self.ai_window(&ctx);

        // Keep ticking so the tray menu responds and the log view stays fresh,
        // even while the window is hidden. Low cost: this only re-reads files.
        ctx.request_repaint_after(Duration::from_millis(400));
    }
}

// ── UI pieces ──────────────────────────────────────────────────────────────
impl RamOptimizerApp {
    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading(
                    egui::RichText::new("● RAM Optimizer").color(egui::Color32::from_rgb(74, 163, 255)),
                );
                ui.separator();
                let (pct, used, total) = self
                    .latest()
                    .map(|r| (r.ram_before_pct, r.ram_before_mb, r.total_mb))
                    .or_else(|| {
                        self.snapshot
                            .as_ref()
                            .map(|s| (s.used_pct, s.used_mb, s.total_mb))
                    })
                    .unwrap_or((0.0, 0, 0));
                let frac = (pct / 100.0) as f32;
                let col = if pct >= 90.0 {
                    egui::Color32::from_rgb(248, 81, 73)
                } else if pct >= 80.0 {
                    egui::Color32::from_rgb(210, 153, 34)
                } else {
                    egui::Color32::from_rgb(63, 185, 80)
                };
                ui.add(
                    egui::ProgressBar::new(frac)
                        .desired_width(280.0)
                        .fill(col)
                        .text(format!("RAM {pct:.0}% ({used}/{total} MB)")),
                );
                ui.label(
                    egui::RichText::new(format!(
                        "· last run {}",
                        ago(self.latest().map(|r| r.ts).unwrap_or(0))
                    ))
                    .weak(),
                );
                let (mon_txt, mon_col) = monitor_badge(&self.sched);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Always-visible background-monitor status; click → Schedule tab.
                    let badge = ui
                        .add(
                            egui::Label::new(egui::RichText::new(mon_txt).color(mon_col).small())
                                .sense(egui::Sense::click()),
                        )
                        .on_hover_text("Background schedule status — click to manage");
                    if badge.clicked() {
                        self.tab = Tab::Schedule;
                    }
                    if let Some(b) = &self.busy {
                        ui.separator();
                        ui.add(egui::Spinner::new());
                        ui.label(egui::RichText::new(b).weak());
                    }
                });
            });
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Overview, "Overview");
                let pend = if self.pending.is_empty() {
                    "Pending".to_string()
                } else {
                    format!("Pending ({})", self.pending.len())
                };
                let resp = ui.selectable_label(self.tab == Tab::Pending, pend);
                if resp.clicked() {
                    self.tab = Tab::Pending;
                }
                ui.selectable_value(&mut self.tab, Tab::Metrics, "Metrics");
                ui.selectable_value(&mut self.tab, Tab::ActionLog, "Action log");
                ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
                ui.selectable_value(&mut self.tab, Tab::Schedule, "Schedule");
            });
            if !self.status_msg.is_empty() {
                let col = if self.status_err {
                    egui::Color32::from_rgb(248, 81, 73)
                } else {
                    egui::Color32::from_rgb(122, 162, 247)
                };
                ui.label(egui::RichText::new(&self.status_msg).color(col).small());
            }
            ui.add_space(2.0);
        });
    }

    fn tab_overview(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if !self.pending.is_empty() {
            let n = self.pending.len();
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new(format!("⚠ {n} action(s) awaiting your confirmation"))
                        .color(egui::Color32::from_rgb(210, 153, 34)),
                );
                if ui.button("Review in Pending →").clicked() {
                    self.tab = Tab::Pending;
                }
            });
            ui.add_space(4.0);
        }
        let busy = self.busy.is_some();
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("▶ Run now (monitor only)"))
                .clicked()
            {
                self.start_pass(
                    ctx,
                    PassOpts {
                        act: false,
                        escalate: false,
                        force_ai: false,
                        alert: false,
                        trigger: "manual-dry".into(),
                    },
                    "Scanning…",
                );
            }
            if ui
                .add_enabled(!busy, egui::Button::new("⚡ Run now + optimize"))
                .clicked()
            {
                self.start_pass(
                    ctx,
                    PassOpts {
                        act: true,
                        escalate: false,
                        force_ai: false,
                        alert: true,
                        trigger: "manual".into(),
                    },
                    "Optimizing…",
                );
            }
            if ui
                .add_enabled(!busy, egui::Button::new("🤖 Ask AI about anomalies"))
                .clicked()
            {
                self.start_pass(
                    ctx,
                    PassOpts {
                        act: false,
                        escalate: false,
                        force_ai: true,
                        alert: false,
                        trigger: "manual-ai".into(),
                    },
                    "Asking AI…",
                );
            }
            ui.label(
                egui::RichText::new("These are the only times this app scans live.")
                    .weak()
                    .small(),
            );
        });
        ui.add_space(6.0);

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            // Findings from the latest run.
            ui.group(|ui| {
                ui.label(egui::RichText::new("LATEST FINDINGS").strong().small());
                match self.latest() {
                    Some(r) if !r.findings.is_empty() => {
                        for f in &r.findings {
                            let col = if f.severity >= 3 {
                                egui::Color32::from_rgb(248, 81, 73)
                            } else {
                                egui::Color32::from_rgb(210, 153, 34)
                            };
                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new("▌").color(col));
                                ui.label(egui::RichText::new(&f.title).strong());
                                ui.label(egui::RichText::new(&f.detail).weak());
                            });
                        }
                    }
                    Some(_) => {
                        ui.label(egui::RichText::new("No anomalies in the last run.").weak());
                    }
                    None => {
                        ui.label(egui::RichText::new("No runs recorded yet. Press a Run button, or install the schedule.").weak());
                    }
                }
            });
            ui.add_space(8.0);

            // Process table from the last saved snapshot (NOT live).
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("PROCESSES (from last scan)").strong().small());
                ui.add(egui::TextEdit::singleline(&mut self.proc_filter).hint_text("filter…").desired_width(200.0));
            });
            let filter = self.proc_filter.to_lowercase();
            if let Some(snap) = &self.snapshot {
                let mut procs: Vec<&collect::Proc> = snap
                    .procs
                    .iter()
                    .filter(|p| {
                        filter.is_empty()
                            || p.name.to_lowercase().contains(&filter)
                            || p.exe.to_lowercase().contains(&filter)
                    })
                    .collect();
                // Always ordered by RAM, largest first (the "▼" marks the sort key).
                procs.sort_by_key(|p| std::cmp::Reverse(p.mem_mb));
                egui::Grid::new("procs").striped(true).num_columns(5).show(ui, |ui| {
                    for h in ["Name", "RAM (MB) ▼", "CPU %", "PID", "Path"] {
                        ui.label(egui::RichText::new(h).strong().small());
                    }
                    ui.end_row();
                    for p in procs.into_iter().take(80) {
                        ui.label(&p.name);
                        ui.label(format!("{}", p.mem_mb));
                        ui.label(format!("{:.0}", p.cpu));
                        ui.label(format!("{}", p.pid));
                        let path = if p.exe.is_empty() { &p.cmd } else { &p.exe };
                        ui.label(egui::RichText::new(path.chars().take(70).collect::<String>()).weak());
                        ui.end_row();
                    }
                });
            } else {
                ui.label(egui::RichText::new("No snapshot yet.").weak());
            }
        });
    }

    fn tab_pending(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.label(
            egui::RichText::new(
                "Confirm-to-act — heuristic detections and AI-escalated strategies queue here. \
                 Nothing is killed until you approve it.",
            )
            .weak()
            .small(),
        );
        ui.add_space(6.0);
        let busy = self.busy.is_some();
        if self.pending.is_empty() {
            ui.label(egui::RichText::new("No actions awaiting confirmation.").weak());
            return;
        }
        // Group proposals by process name (biggest total first) so a dozen
        // msedgewebview2.exe / chrome.exe duplicates collapse into ONE row with a
        // batch "Approve & kill all", instead of a dozen separate approvals.
        let mut order: Vec<String> = Vec::new();
        let mut groups: std::collections::HashMap<String, Vec<&actions::Proposal>> =
            std::collections::HashMap::new();
        for p in &self.pending {
            if !groups.contains_key(&p.name) {
                order.push(p.name.clone());
            }
            groups.entry(p.name.clone()).or_default().push(p);
        }
        order.sort_by_key(|n| std::cmp::Reverse(groups[n].iter().map(|p| p.mem_mb).sum::<u64>()));

        let mut approve: Option<String> = None;
        let mut dismiss: Option<String> = None;
        let mut approve_grp: Option<String> = None;
        let mut dismiss_grp: Option<String> = None;
        let mut block_grp: Option<String> = None;
        let right = egui::Layout::right_to_left(egui::Align::Center);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for name in &order {
                    let items = &groups[name];
                    let total_mb: u64 = items.iter().map(|p| p.mem_mb).sum();
                    ui.group(|ui| {
                        if items.len() == 1 {
                            let p = items[0];
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(format!("kill {}", p.name)).strong());
                                ui.label(
                                    egui::RichText::new(format!(
                                        "pid {} · ~{} MB",
                                        p.pid, p.mem_mb
                                    ))
                                    .weak(),
                                );
                                ui.with_layout(right, |ui| {
                                    if ui
                                        .add_enabled(!busy, egui::Button::new("🚫 Block"))
                                        .on_hover_text(
                                            "Kill now and auto-kill it every pass (soft block)",
                                        )
                                        .clicked()
                                    {
                                        block_grp = Some(p.name.clone());
                                    }
                                    if ui
                                        .add_enabled(!busy, egui::Button::new("✕ Dismiss"))
                                        .clicked()
                                    {
                                        dismiss = Some(p.id.clone());
                                    }
                                    if ui
                                        .add_enabled(!busy, egui::Button::new("✓ Approve & kill"))
                                        .clicked()
                                    {
                                        approve = Some(p.id.clone());
                                    }
                                });
                            });
                            ui.label(
                                egui::RichText::new(format!("source: {} · {}", p.source, p.reason))
                                    .small(),
                            );
                        } else {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("kill {}× {}", items.len(), name))
                                        .strong(),
                                );
                                ui.label(
                                    egui::RichText::new(format!("~{} MB total", total_mb)).weak(),
                                );
                                ui.with_layout(right, |ui| {
                                    if ui
                                        .add_enabled(!busy, egui::Button::new("🚫 Block app"))
                                        .on_hover_text(
                                            "Kill all now and auto-kill this app every pass \
                                             (soft block)",
                                        )
                                        .clicked()
                                    {
                                        block_grp = Some(name.clone());
                                    }
                                    if ui
                                        .add_enabled(!busy, egui::Button::new("✕ Dismiss all"))
                                        .clicked()
                                    {
                                        dismiss_grp = Some(name.clone());
                                    }
                                    if ui
                                        .add_enabled(
                                            !busy,
                                            egui::Button::new(format!(
                                                "✓ Approve & kill all ({})",
                                                items.len()
                                            )),
                                        )
                                        .clicked()
                                    {
                                        approve_grp = Some(name.clone());
                                    }
                                });
                            });
                            ui.label(
                                egui::RichText::new(format!(
                                    "source: {} · {} instances",
                                    items[0].source,
                                    items.len()
                                ))
                                .small(),
                            );
                            egui::CollapsingHeader::new(format!("show {} processes", items.len()))
                                .id_source(format!("grp-{name}"))
                                .show(ui, |ui| {
                                    for p in items {
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "pid {} · ~{} MB",
                                                    p.pid, p.mem_mb
                                                ))
                                                .small(),
                                            );
                                            ui.with_layout(right, |ui| {
                                                if ui
                                                    .add_enabled(!busy, egui::Button::new("✕"))
                                                    .on_hover_text("Dismiss")
                                                    .clicked()
                                                {
                                                    dismiss = Some(p.id.clone());
                                                }
                                                if ui
                                                    .add_enabled(!busy, egui::Button::new("✓"))
                                                    .on_hover_text("Approve & kill")
                                                    .clicked()
                                                {
                                                    approve = Some(p.id.clone());
                                                }
                                            });
                                        });
                                    }
                                });
                        }
                    });
                }
            });

        // One action per frame (block, then group actions, take priority).
        if let Some(name) = block_grp {
            self.block_and_kill(ctx, name);
        } else if let Some(name) = approve_grp {
            self.start_approve_group(ctx, name);
        } else if let Some(name) = dismiss_grp {
            let n = actions::dismiss_group(&name);
            self.pending = actions::load();
            self.status_msg = format!("Dismissed {n} proposal(s).");
            self.status_err = false;
        } else if let Some(id) = approve {
            self.start_approve(ctx, id);
        } else if let Some(id) = dismiss {
            actions::dismiss(&id);
            self.pending = actions::load();
            self.status_msg = "Dismissed.".into();
            self.status_err = false;
        }
    }

    fn tab_metrics(&mut self, ui: &mut egui::Ui) {
        let s = &self.summary;
        let g = |k: &str| s.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0);
        ui.horizontal_wrapped(|ui| {
            let card = |ui: &mut egui::Ui, label: &str, val: String| {
                ui.group(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(val).heading());
                        ui.label(egui::RichText::new(label).weak().small());
                    });
                });
            };
            card(ui, "runs recorded", format!("{}", g("runs") as u64));
            card(ui, "runs that acted", format!("{}", g("actedRuns") as u64));
            card(
                ui,
                "total reclaimed (MB)",
                format!("{}", g("totalReclaimedMB") as u64),
            );
            card(
                ui,
                "avg duration (ms)",
                format!("{}", g("avgDurationMs") as u64),
            );
            card(
                ui,
                "avg RAM reduced / acting run",
                format!("{:.2}%", g("avgReducedPctWhenActed")),
            );
            card(ui, "AI escalations", format!("{}", g("aiRuns") as u64));
            card(
                ui,
                "strategies saved",
                format!("{}", g("strategiesSaved") as u64),
            );
        });
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new("PER-RUN METRICS (newest first)")
                .strong()
                .small(),
        );
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("metrics")
                    .striped(true)
                    .num_columns(9)
                    .show(ui, |ui| {
                        for h in [
                            "When",
                            "Trigger",
                            "Dur ms",
                            "RAM before",
                            "RAM after",
                            "Reclaimed MB",
                            "Reduced %",
                            "Findings",
                            "Self CPU%",
                        ] {
                            ui.label(egui::RichText::new(h).strong().small());
                        }
                        ui.end_row();
                        for r in self.runs.iter().rev() {
                            ui.label(ago(r.ts));
                            ui.label(&r.trigger);
                            ui.label(format!("{}", r.duration_ms));
                            ui.label(format!("{:.0}%", r.ram_before_pct));
                            ui.label(format!("{:.0}%", r.ram_after_pct));
                            ui.label(format!("{}", r.reclaimed_mb));
                            ui.label(format!("{:.2}", r.reduced_pct));
                            ui.label(format!("{}", r.findings.len()));
                            ui.label(format!("{:.1}", r.self_cpu_pct));
                            ui.end_row();
                        }
                    });
            });
    }

    fn tab_action_log(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.label(egui::RichText::new("RUN HISTORY — methods, AI prompts, and strategies written to the vector DB").strong().small());
            for (i, r) in self.runs.iter().rev().enumerate() {
                let header = format!(
                    "{} · {} · {} finding(s) · {} action(s){}",
                    ago(r.ts),
                    r.trigger,
                    r.findings.len(),
                    r.actions.len(),
                    if r.ai.is_some() { " · AI" } else { "" }
                );
                egui::CollapsingHeader::new(header).id_source(("run", i)).default_open(i == 0).show(ui, |ui| {
                    if !r.actions.is_empty() {
                        ui.label(egui::RichText::new("Optimizer actions:").strong().small());
                        for a in &r.actions {
                            ui.label(format!("• {a}"));
                        }
                    }
                    if !r.findings.is_empty() {
                        ui.label(egui::RichText::new("Findings:").strong().small());
                        for f in &r.findings {
                            ui.label(format!("• [{}] {} — {}", f.kind, f.title, f.detail));
                        }
                    }
                    if let Some(ai) = &r.ai {
                        ui.separator();
                        ui.label(egui::RichText::new(format!("AI · provider={} model={} ({} char prompt)", ai.provider, ai.model, ai.prompt_chars)).strong().small());
                        if !ai.advice.is_empty() {
                            ui.label(egui::RichText::new(format!("Advice: {}", ai.advice)).color(egui::Color32::from_rgb(122, 162, 247)));
                        }
                        egui::CollapsingHeader::new("Prompt sent").id_source(("prompt", i)).show(ui, |ui| {
                            ui.add(egui::TextEdit::multiline(&mut ai.prompt.clone()).code_editor().desired_rows(6).desired_width(f32::INFINITY));
                        });
                    }
                    if !r.strategies.is_empty() {
                        ui.label(egui::RichText::new(format!("Strategies written to vector DB ({}):", r.strategies.len())).strong().small());
                        for st in &r.strategies {
                            ui.label(egui::RichText::new(format!("• {} — {}", st.id, st.text)).weak());
                        }
                    }
                });
            }
            ui.add_space(10.0);
            ui.collapsing("Raw log (~/.ram-optimizer/ram-optimizer.log)", |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.log.join("\n"))
                        .code_editor()
                        .desired_rows(12)
                        .desired_width(f32::INFINITY),
                );
            });
        });
    }

    fn tab_settings(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.group(|ui| {
                ui.label(egui::RichText::new("OPTIMIZER & THRESHOLDS").strong().small());
                ui.checkbox(&mut self.form.optimize_enabled, "Optimizer enabled (allow kill/restart rule actions)");
                egui::Grid::new("th").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                    ui.label("System RAM alert % (gentle: warn + propose)");
                    ui.add(egui::DragValue::new(&mut self.form.sys_ram_pct).clamp_range(1.0..=100.0));
                    ui.end_row();
                    ui.label("Auto-act RAM % (aggressive: auto-kill; 0 = off)");
                    ui.add(egui::DragValue::new(&mut self.form.auto_act_pct).clamp_range(0.0..=100.0));
                    ui.end_row();
                    ui.label("Auto-act confirm passes (wait N critical passes before killing)");
                    ui.add(egui::DragValue::new(&mut self.form.auto_act_confirm_passes).clamp_range(1..=20));
                    ui.end_row();
                    ui.label("High RAM (MB)");
                    ui.add(egui::DragValue::new(&mut self.form.high_ram_mb));
                    ui.end_row();
                    ui.label("High CPU %");
                    ui.add(egui::DragValue::new(&mut self.form.high_cpu_pct).clamp_range(1.0..=100.0));
                    ui.end_row();
                    ui.label("Single-proc RAM %");
                    ui.add(egui::DragValue::new(&mut self.form.single_proc_pct).clamp_range(1.0..=100.0));
                    ui.end_row();
                    ui.label("Duplicate count");
                    ui.add(egui::DragValue::new(&mut self.form.dup_count));
                    ui.end_row();
                });
                ui.checkbox(
                    &mut self.form.pause_antimalware_when_idle,
                    "Pause Windows Defender when idle (reclaim RAM under memory pressure — off by default, weakens antivirus protection)",
                );
                ui.label(
                    egui::RichText::new(
                        "Only acts when RAM is under pressure AND Defender confirms no active threats. \
                         Requires the background task to run elevated — see the Schedule tab.",
                    )
                    .weak()
                    .small(),
                );
                ui.label(egui::RichText::new("Ignore names (one per line)").weak().small());
                ui.add(egui::TextEdit::multiline(&mut self.form.ignore_names).desired_rows(4).desired_width(f32::INFINITY));
            });

            ui.group(|ui| {
                ui.label(egui::RichText::new("NOTIFICATIONS & WINDOW").strong().small());
                ui.checkbox(&mut self.form.alerts_toast, "Show OS notifications (toasts) for findings & reclaim actions");
                ui.checkbox(&mut self.form.ui_start_hidden, "Start hidden in the tray — don't auto-show the window on launch");
                ui.label(
                    egui::RichText::new(
                        "When hidden, open the dashboard from the tray icon. `ram-optimizer ui` always shows it; \
                         the background monitor runs regardless.",
                    )
                    .weak()
                    .small(),
                );
            });

            ui.group(|ui| {
                ui.label(egui::RichText::new("AI ESCALATION").strong().small());
                ui.checkbox(&mut self.form.ai_enabled, "Enabled");
                egui::ComboBox::from_label("Provider")
                    .selected_text(&self.form.ai_provider)
                    .show_ui(ui, |ui| {
                        for p in ["openai", "groq", "claude"] {
                            ui.selectable_value(&mut self.form.ai_provider, p.to_string(), p);
                        }
                    });
                ui.horizontal(|ui| {
                    ui.label("OpenAI key");
                    ui.add(egui::TextEdit::singleline(&mut self.form.openai_key).password(true).hint_text(if self.form.openai_set { "•••• set — blank keeps" } else { "leave blank" }));
                });
                ui.horizontal(|ui| {
                    ui.label("Groq key");
                    ui.add(egui::TextEdit::singleline(&mut self.form.groq_key).password(true).hint_text(if self.form.groq_set { "•••• set — blank keeps" } else { "leave blank" }));
                });
                ui.label(egui::RichText::new("Keys are write-only here: stored in your local config.json, never shown back.").weak().small());
            });

            ui.group(|ui| {
                ui.label(egui::RichText::new("VECTOR DB MEMORY (Upstash)").strong().small());
                ui.checkbox(&mut self.form.vdb_enabled, "Enabled (store AI strategies + retrieve similar past incidents)");
                ui.horizontal(|ui| {
                    ui.label("REST URL");
                    ui.add(egui::TextEdit::singleline(&mut self.form.vdb_url).hint_text("blank = built-in shared default").desired_width(420.0));
                });
                ui.horizontal(|ui| {
                    ui.label("Token");
                    ui.add(egui::TextEdit::singleline(&mut self.form.vdb_token).password(true).hint_text(if self.form.vdb_token_set { "•••• set — blank keeps" } else { "blank = built-in default" }));
                });
                if self.vdb_default {
                    ui.label(egui::RichText::new("Using the built-in shared default index (treat it as public — set your own URL/token to opt out).").color(egui::Color32::from_rgb(210, 153, 34)).small());
                }
            });

            ui.group(|ui| {
                ui.label(egui::RichText::new("RULES (JSON array)").strong().small());
                ui.add(egui::TextEdit::multiline(&mut self.form.rules_json).code_editor().desired_rows(10).desired_width(f32::INFINITY));
            });

            ui.horizontal(|ui| {
                if ui.button("💾 Save settings").clicked() {
                    self.apply_settings();
                }
                if ui.button("↺ Reload from disk").clicked() {
                    self.cfg = config::load_config();
                    self.reload();
                    self.load_form();
                    self.status_msg = "Reloaded config.json.".into();
                    self.status_err = false;
                }
            });
        });
    }

    fn tab_schedule(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let busy = self.busy.is_some();
        ui.group(|ui| {
            ui.label(egui::RichText::new("BACKGROUND SCHEDULE").strong().small());
            let s = &self.sched;
            ui.label(format!("Platform: {}", s.platform));
            ui.label(format!(
                "Installed: {}   ·   Running: {}   ·   Interval: every {} min",
                s.installed, s.enabled, s.interval_minutes
            ));
            ui.label(egui::RichText::new(&s.detail).weak());
            if !s.task_run.is_empty() {
                // Which build/folder the single named task actually runs — opening
                // the app re-points this at the current build, so there's never a
                // second optimizer from another checkout.
                ui.label(
                    egui::RichText::new(format!("Runs: {}", s.task_run))
                        .weak()
                        .small(),
                );
            }
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "The optimizer runs from the OS scheduler in the background. Opening this app \
                     auto-starts it; closing the app (or Tray ▸ Quit) does NOT stop it — only the \
                     Stop button below does (until the next time you open the app).",
                )
                .color(egui::Color32::from_rgb(122, 162, 247))
                .small(),
            );
        });

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("⚡ Trigger run now"))
                .clicked()
            {
                self.start_pass(
                    ctx,
                    PassOpts {
                        act: true,
                        escalate: false,
                        force_ai: false,
                        alert: true,
                        trigger: "manual".into(),
                    },
                    "Running a pass now…",
                );
            }
            ui.label(
                egui::RichText::new(
                    "Runs one pass immediately (same as a scheduled run: detect + your kill/restart rules).",
                )
                .weak()
                .small(),
            );
        });

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Run every");
            ui.add(
                egui::DragValue::new(&mut self.sched_interval)
                    .clamp_range(1..=1440)
                    .suffix(" min"),
            );
            if ui
                .add_enabled(!busy, egui::Button::new("Apply interval"))
                .clicked()
            {
                let n = self.sched_interval;
                self.start_sched(ctx, true, Some(n), "Updating schedule…");
            }
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("▶ Start / install schedule"))
                .clicked()
            {
                let n = self.sched_interval;
                self.start_sched(ctx, true, Some(n), "Starting schedule…");
            }
            if ui
                .add_enabled(!busy, egui::Button::new("⏹ Stop schedule"))
                .clicked()
            {
                self.start_sched(ctx, false, None, "Stopping schedule…");
            }
        });
        ui.add_space(12.0);
        ui.group(|ui| {
            ui.label(egui::RichText::new("ELEVATED INSTALL (OPTIONAL)").strong().small());
            ui.label(
                egui::RichText::new(
                    "By default the background task runs as your regular user — no admin needed. \
                     Some features (e.g. pausing Windows Defender) require the task to run elevated. \
                     Run the command below once in PowerShell to re-register it with highest privileges:",
                )
                .weak()
                .small(),
            );
            ui.add_space(4.0);

            // Resolve the scripts directory relative to the running exe.
            let scripts_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            let scripts_path = scripts_dir.join("scripts").join("install-windows.ps1");
            let cmd = format!(
                "powershell -ExecutionPolicy Bypass -File \"{}\" -Elevated",
                scripts_path.display()
            );

            // Monospace code display.
            ui.add(
                egui::TextEdit::singleline(&mut cmd.clone())
                    .code_editor()
                    .desired_width(f32::INFINITY)
                    .interactive(false),
            );

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("📋 Copy command").clicked() {
                    ui.output_mut(|o| o.copied_text = cmd.clone());
                }

                #[cfg(windows)]
                if ui.button("⬛ Open PowerShell here").clicked() {
                    let dir = scripts_dir.clone();
                    let _ = std::process::Command::new("powershell")
                        .args([
                            "-NoExit",
                            "-Command",
                            &format!(
                                "Set-Location \"{}\"; Set-Clipboard -Value '{}'; Write-Host \
                                 'Command copied to clipboard — paste it here and press Enter to run.' \
                                 -ForegroundColor Cyan",
                                dir.display(),
                                cmd
                            ),
                        ])
                        .spawn();
                }

                ui.label(
                    egui::RichText::new("Opens a terminal at the right folder and pre-copies the command for you.")
                        .weak()
                        .small(),
                );
            });
        });
    }

    fn ai_window(&mut self, ctx: &egui::Context) {
        if !self.show_ai {
            return;
        }
        let mut open = self.show_ai;
        egui::Window::new("AI diagnosis")
            .open(&mut open)
            .default_width(560.0)
            .collapsible(false)
            .show(ctx, |ui| {
                if let Some(ai) = &self.ai_rec {
                    ui.label(
                        egui::RichText::new(format!(
                            "provider={} · model={}",
                            ai.provider, ai.model
                        ))
                        .weak()
                        .small(),
                    );
                    if !ai.advice.is_empty() {
                        ui.label(egui::RichText::new("Advice").strong());
                        ui.label(
                            egui::RichText::new(&ai.advice)
                                .color(egui::Color32::from_rgb(122, 162, 247)),
                        );
                        ui.separator();
                    } else {
                        ui.label(
                            egui::RichText::new(
                                "AI is off — here is the prompt to paste into your own assistant:",
                            )
                            .weak()
                            .small(),
                        );
                    }
                    ui.label(egui::RichText::new("Prompt").strong());
                    ui.add(
                        egui::TextEdit::multiline(&mut ai.prompt.clone())
                            .code_editor()
                            .desired_rows(12)
                            .desired_width(f32::INFINITY),
                    );
                } else {
                    ui.label("No AI output.");
                }
            });
        self.show_ai = open;
    }
}
