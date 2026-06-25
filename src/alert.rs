//! Alerting: append to ~/.ram-optimizer/ram-optimizer.log (not rate-limited) + a native
//! OS notification (rate-limited by cooldown, but a novel kind always alerts now).
use crate::config::{state_dir, Config};
use crate::detect::Finding;
use crate::state::Meta;
#[cfg(windows)]
use crate::util::hidden_command;
use crate::util::now_epoch;
use std::collections::HashSet;
use std::path::Path;

/// `allow_toast` lets the caller suppress the OS popup (e.g. when system RAM is
/// below the non-aggressive band and `alerts.onlyUnderRamPressure` is set) while
/// still recording the finding to the log.
pub fn emit(
    findings: &[Finding],
    advice: Option<&str>,
    cfg: &Config,
    meta: &mut Meta,
    allow_toast: bool,
) {
    if findings.is_empty() {
        return;
    }
    let (title, body) = summarize(findings, advice);
    if cfg.alerts.log {
        log_line(findings, advice);
    }
    if cfg.alerts.toast && allow_toast {
        let cooldown = cfg.alerts.cooldown_minutes.saturating_mul(60);
        let now = now_epoch();
        // Unique kinds, insertion-ordered.
        let mut kinds: Vec<String> = Vec::new();
        for f in findings {
            if !kinds.contains(&f.kind) {
                kinds.push(f.kind.clone());
            }
        }
        let prev: HashSet<&String> = meta.last_kinds.iter().collect();
        let has_new_kind = kinds.iter().any(|k| !prev.contains(k));
        if has_new_kind || now.saturating_sub(meta.last_alert_epoch) >= cooldown {
            toast(&title, &body);
            meta.last_alert_epoch = now;
        }
        meta.last_kinds = kinds;
    }
}

/// Standalone toast (used by the optimizer to announce reclaim actions).
pub fn notify(title: &str, body: &str) {
    toast(title, body);
}

fn summarize(findings: &[Finding], advice: Option<&str>) -> (String, String) {
    let high = findings.iter().filter(|f| f.severity >= 3).count();
    let title = if high > 0 {
        format!("⚠ RAM Optimizer: {} issue(s), {} high", findings.len(), high)
    } else {
        format!("RAM Optimizer: {} issue(s)", findings.len())
    };
    let mut lines: Vec<String> = findings
        .iter()
        .take(4)
        .map(|f| format!("• {} — {}", f.title, f.suggestion))
        .collect();
    if findings.len() > 4 {
        lines.push(format!("…and {} more", findings.len() - 4));
    }
    if let Some(a) = advice {
        lines.push(format!("AI: {}", first_line(a, 160)));
    }
    (title, lines.join("\n"))
}

fn log_line(findings: &[Finding], advice: Option<&str>) {
    let p = state_dir().join("ram-optimizer.log");
    let mut s = format!("[{}] {} finding(s):", now_epoch(), findings.len());
    for f in findings {
        s.push_str(&format!(
            "\n  ({}) {} :: {} :: {}",
            f.kind, f.title, f.detail, f.suggestion
        ));
    }
    if let Some(a) = advice {
        s.push_str(&format!("\n  AI> {}", a.replace('\n', " ")));
    }
    s.push('\n');
    let _ = append_file(&p, &s);
}

fn toast(title: &str, body: &str) {
    #[cfg(windows)]
    {
        let ps = format!(
            "Add-Type -AssemblyName System.Windows.Forms;\
             $n=New-Object System.Windows.Forms.NotifyIcon;\
             $n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;\
             $n.ShowBalloonTip(10000, {}, {}, [System.Windows.Forms.ToolTipIcon]::Warning);\
             Start-Sleep -Seconds 8;$n.Dispose()",
            ps_str(title),
            ps_str(body)
        );
        let _ = hidden_command("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command"])
            .arg(&ps)
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification {} with title {}",
            osa_str(body),
            osa_str(title)
        );
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .spawn();
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("notify-send")
            .arg(title)
            .arg(body)
            .spawn();
    }
}

fn first_line(s: &str, max: usize) -> String {
    s.lines().next().unwrap_or("").chars().take(max).collect()
}

#[cfg(windows)]
fn ps_str(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(target_os = "macos")]
fn osa_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn append_file(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(content.as_bytes())
}
