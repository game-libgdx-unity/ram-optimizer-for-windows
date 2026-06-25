//! Control the OS scheduler entry that runs RAM Optimizer every N minutes — from the
//! dashboard, no terminal needed. RAM Optimizer itself is still a no-daemon one-shot;
//! this module just installs / enables / disables / re-intervals the scheduler
//! task (Windows Task Scheduler, macOS LaunchAgent, Linux crontab).
//!
//! Creating a per-user task here does NOT require admin/sudo (unlike the
//! `--RunLevel Highest` install script). If an action does need elevation, the
//! raw OS error is returned so the UI can show it.
use crate::config::Config;
#[cfg(windows)]
use crate::util::hidden_command;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SchedStatus {
    pub installed: bool,
    pub enabled: bool,
    pub interval_minutes: u64,
    pub platform: String,
    pub detail: String,
    /// The command the installed task runs (best-effort) — so the UI can show
    /// WHICH build/folder is scheduled. Empty when not installed / unknown.
    pub task_run: String,
}

fn exe_path() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("ram-optimizer"))
}

/// Ensure the background schedule is installed and enabled — called when the
/// dashboard opens so launching the app also gets the monitor running. It's a
/// no-op status report when the task is already installed and enabled; it
/// installs the task when missing, or re-enables one that was disabled. Uses the
/// per-platform `status` / `set_interval` / `set_enabled` below.
pub fn autostart(cfg: &Config) -> Result<String, String> {
    let st = status(cfg);
    if !st.installed {
        // Not installed yet — create + enable it at the configured interval.
        return set_interval(cfg, cfg.schedule.interval_minutes);
    }
    // A task with this name already exists. The scheduler keys tasks by NAME
    // (default "RamOptimizer"), so opening a second copy NEVER creates a second
    // task — but the existing one may point at a DIFFERENT build (e.g. an older
    // checkout in another folder). Re-point it at THIS build so exactly one
    // optimizer ever runs, and it's the one you just opened.
    if stale_target(cfg) {
        let name = &cfg.schedule.task_name;
        let min = cfg.schedule.interval_minutes;
        return set_interval(cfg, min).map(|_| {
            format!(
                "Re-pointed the existing '{name}' task to THIS build (every {min} min) — \
                 no duplicate task created."
            )
        });
    }
    if st.enabled {
        Ok(format!(
            "Background monitor already running (every {} min).",
            st.interval_minutes
        ))
    } else {
        // Present, points here, but disabled — turn it back on.
        set_enabled(cfg, true)
    }
}

/// True when an installed task with our name exists but its command does NOT
/// reference this build's run target (so it belongs to a different/older copy and
/// should be re-pointed). Conservatively false when we can't read the task or off
/// Windows (other platforms always (re)write their own entry on autostart).
#[cfg(windows)]
fn stale_target(cfg: &Config) -> bool {
    let name = &cfg.schedule.task_name;
    let out = hidden_command("schtasks")
        .args(["/Query", "/TN", name, "/FO", "LIST", "/V"])
        .output();
    let txt = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_lowercase(),
        _ => return false, // can't tell — don't churn the task
    };
    let here_exe = exe_path().display().to_string().to_lowercase();
    let here_vbs = run_hidden_vbs().map(|p| p.display().to_string().to_lowercase());
    let points_here =
        txt.contains(&here_exe) || here_vbs.as_deref().is_some_and(|v| txt.contains(v));
    !points_here
}

#[cfg(not(windows))]
fn stale_target(_cfg: &Config) -> bool {
    false
}

/// Locate scripts/run-hidden.vbs next to the build tree (target/release/.. -> root/scripts).
#[cfg(windows)]
fn run_hidden_vbs() -> Option<PathBuf> {
    let exe = exe_path();
    let root = exe.parent()?.parent()?.parent()?; // release -> target -> repo root
    let vbs = root.join("scripts").join("run-hidden.vbs");
    if vbs.exists() {
        Some(vbs)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Windows (schtasks)
// ---------------------------------------------------------------------------
#[cfg(windows)]
pub fn status(cfg: &Config) -> SchedStatus {
    let name = &cfg.schedule.task_name;
    let out = hidden_command("schtasks")
        .args(["/Query", "/TN", name, "/FO", "LIST", "/V"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let txt = String::from_utf8_lossy(&o.stdout);
            let disabled = txt.contains("Disabled");
            SchedStatus {
                installed: true,
                enabled: !disabled,
                interval_minutes: cfg.schedule.interval_minutes,
                platform: "windows".into(),
                task_run: extract_run_line(&txt),
                detail: if disabled {
                    "Task present but disabled.".into()
                } else {
                    "Task present and enabled.".into()
                },
            }
        }
        _ => SchedStatus {
            installed: false,
            enabled: false,
            interval_minutes: cfg.schedule.interval_minutes,
            platform: "windows".into(),
            task_run: String::new(),
            detail: "No scheduled task installed yet.".into(),
        },
    }
}

/// Pull the "Task To Run" command out of `schtasks /V` verbose output. Picks the
/// line that names our launcher (locale-independent — matched on the path tokens,
/// not the field label) and strips the English label prefix when present.
#[cfg(windows)]
fn extract_run_line(txt: &str) -> String {
    for line in txt.lines() {
        let low = line.to_lowercase();
        if low.contains("run-hidden.vbs") || low.contains("ram-optimizer.exe") {
            let t = line.trim();
            return t
                .strip_prefix("Task To Run:")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| t.to_string());
        }
    }
    String::new()
}

/// Turn a raw `schtasks` failure into an actionable message. The common one is
/// "Access is denied": the task was created elevated (RunLevel Highest, e.g. by
/// `install-windows.ps1`), but the dashboard runs non-elevated and Windows won't
/// let it modify an admin-owned task.
#[cfg(windows)]
fn schtasks_err(stderr: &[u8], name: &str) -> String {
    let raw = String::from_utf8_lossy(stderr).trim().to_string();
    if raw.to_lowercase().contains("denied") {
        format!(
            "{raw} — the '{name}' task is admin-owned (created elevated). To manage it \
             here, delete it once from an elevated terminal \
             (`schtasks /Delete /TN {name} /F`) and reopen RAM Optimizer so it re-installs \
             a per-user task — or run the dashboard as administrator."
        )
    } else if raw.is_empty() {
        "schtasks failed (no error text).".into()
    } else {
        raw
    }
}

#[cfg(windows)]
fn run_target() -> String {
    match run_hidden_vbs() {
        // The VBS itself invokes the exe with --once (headless, no window).
        Some(vbs) => format!("wscript.exe \"{}\"", vbs.display()),
        // No VBS: call the exe directly, with --once so it does a headless pass
        // instead of opening the dashboard.
        None => format!("\"{}\" --once", exe_path().display()),
    }
}

#[cfg(windows)]
pub fn set_interval(cfg: &Config, minutes: u64) -> Result<String, String> {
    let minutes = minutes.clamp(1, 1440);
    let name = &cfg.schedule.task_name;
    let out = hidden_command("schtasks")
        .args([
            "/Create",
            "/TN",
            name,
            "/TR",
            &run_target(),
            "/SC",
            "MINUTE",
            "/MO",
            &minutes.to_string(),
            "/F",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(format!("Scheduled '{name}' to run every {minutes} min."))
    } else {
        Err(schtasks_err(&out.stderr, name))
    }
}

#[cfg(windows)]
pub fn set_enabled(cfg: &Config, on: bool) -> Result<String, String> {
    let name = &cfg.schedule.task_name;
    if on && !status(cfg).installed {
        return set_interval(cfg, cfg.schedule.interval_minutes);
    }
    let flag = if on { "/ENABLE" } else { "/DISABLE" };
    let out = hidden_command("schtasks")
        .args(["/Change", "/TN", name, flag])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(format!(
            "Scheduled task '{name}' {}.",
            if on { "started" } else { "stopped" }
        ))
    } else {
        Err(schtasks_err(&out.stderr, name))
    }
}

// ---------------------------------------------------------------------------
// macOS (LaunchAgent)
// ---------------------------------------------------------------------------
#[cfg(target_os = "macos")]
fn plist_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library/LaunchAgents/com.ram-optimizer.monitor.plist")
}

#[cfg(target_os = "macos")]
fn write_plist(minutes: u64) -> std::io::Result<PathBuf> {
    let p = plist_path();
    let exe = exe_path();
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let log = home.join(".ram-optimizer/cron.log");
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\"><dict>\n\
  <key>Label</key><string>com.ram-optimizer.monitor</string>\n\
  <key>ProgramArguments</key><array><string>{}</string><string>--once</string></array>\n\
  <key>StartInterval</key><integer>{}</integer>\n\
  <key>StandardOutPath</key><string>{}</string>\n\
  <key>StandardErrorPath</key><string>{}</string>\n\
</dict></plist>\n",
        exe.display(),
        minutes.max(1) * 60,
        log.display(),
        log.display()
    );
    std::fs::write(&p, body)?;
    Ok(p)
}

#[cfg(target_os = "macos")]
pub fn status(cfg: &Config) -> SchedStatus {
    let installed = plist_path().exists();
    let listed = std::process::Command::new("launchctl")
        .arg("list")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("com.ram-optimizer.monitor"))
        .unwrap_or(false);
    SchedStatus {
        installed,
        enabled: listed,
        interval_minutes: cfg.schedule.interval_minutes,
        platform: "macos".into(),
        task_run: if installed {
            format!("{} --once", exe_path().display())
        } else {
            String::new()
        },
        detail: if installed {
            format!("LaunchAgent present; loaded={listed}.")
        } else {
            "No LaunchAgent installed yet.".into()
        },
    }
}

#[cfg(target_os = "macos")]
pub fn set_interval(cfg: &Config, minutes: u64) -> Result<String, String> {
    let p = write_plist(minutes).map_err(|e| e.to_string())?;
    let _ = std::process::Command::new("launchctl")
        .args(["unload", &p.display().to_string()])
        .output();
    let out = std::process::Command::new("launchctl")
        .args(["load", &p.display().to_string()])
        .output()
        .map_err(|e| e.to_string())?;
    let _ = cfg;
    if out.status.success() {
        Ok(format!("LaunchAgent set to every {minutes} min."))
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(target_os = "macos")]
pub fn set_enabled(cfg: &Config, on: bool) -> Result<String, String> {
    if on {
        return set_interval(cfg, cfg.schedule.interval_minutes);
    }
    let p = plist_path();
    let out = std::process::Command::new("launchctl")
        .args(["unload", &p.display().to_string()])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok("LaunchAgent stopped (unloaded).".into())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

// ---------------------------------------------------------------------------
// Linux (crontab)
// ---------------------------------------------------------------------------
#[cfg(all(not(windows), not(target_os = "macos")))]
fn cron_lines() -> Vec<String> {
    std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn write_cron(lines: &[String]) -> Result<(), String> {
    use std::io::Write;
    let mut child = std::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut si) = child.stdin.take() {
        let body = lines.join("\n");
        let _ = si.write_all(body.as_bytes());
        let _ = si.write_all(b"\n");
    }
    let st = child.wait().map_err(|e| e.to_string())?;
    if st.success() {
        Ok(())
    } else {
        Err("crontab write failed".into())
    }
}

#[cfg(all(not(windows), not(target_os = "macos")))]
pub fn status(cfg: &Config) -> SchedStatus {
    let exe = exe_path().display().to_string();
    let line = cron_lines()
        .into_iter()
        .find(|l| l.contains(&exe) && !l.trim_start().starts_with('#'));
    let present = line.is_some();
    SchedStatus {
        installed: present,
        enabled: present,
        interval_minutes: cfg.schedule.interval_minutes,
        platform: "linux".into(),
        task_run: line.unwrap_or_default(),
        detail: if present {
            "Crontab entry present.".into()
        } else {
            "No crontab entry installed yet.".into()
        },
    }
}

#[cfg(all(not(windows), not(target_os = "macos")))]
pub fn set_interval(cfg: &Config, minutes: u64) -> Result<String, String> {
    let minutes = minutes.clamp(1, 1440);
    let exe = exe_path().display().to_string();
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let log = home.join(".ram-optimizer/cron.log");
    let line = format!(
        "*/{minutes} * * * * \"{exe}\" --once >> \"{}\" 2>&1",
        log.display()
    );
    let mut lines: Vec<String> = cron_lines()
        .into_iter()
        .filter(|l| !l.contains(&exe))
        .collect();
    lines.push(line);
    write_cron(&lines)?;
    let _ = cfg;
    Ok(format!("Crontab set to every {minutes} min."))
}

#[cfg(all(not(windows), not(target_os = "macos")))]
pub fn set_enabled(cfg: &Config, on: bool) -> Result<String, String> {
    if on {
        return set_interval(cfg, cfg.schedule.interval_minutes);
    }
    let exe = exe_path().display().to_string();
    let lines: Vec<String> = cron_lines()
        .into_iter()
        .filter(|l| !l.contains(&exe))
        .collect();
    write_cron(&lines)?;
    Ok("Crontab entry removed (stopped).".into())
}
