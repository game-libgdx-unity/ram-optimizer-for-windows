//! Optional, opt-in taming of the Windows antimalware service — Microsoft
//! Defender, service `WinDefend`, process `MsMpEng.exe` (the "Antimalware Service
//! Executable" that periodically pins RAM/CPU while scanning).
//!
//! When the user turns on `optimize.pauseAntimalwareWhenIdle` and a pass finds the
//! machine under RAM pressure with that service running hot, the optimizer will —
//! **only after Defender confirms there are no active threats** — attempt to stop
//! the service to reclaim resources. See `optimize::tame_antimalware`.
//!
//! Safety / honesty notes (this matters — the action weakens antivirus):
//!   * Off by default; the user must opt in explicitly in `config.json`.
//!   * We act on a *positive* "no active threats" signal only. If threat status
//!     can't be determined ([`ThreatStatus::Unknown`]), the service is left alone.
//!   * On a normally-configured box, **Tamper Protection** (on by default) blocks
//!     stopping `WinDefend` even when elevated — by design, so malware can't
//!     disable AV. In that case [`pause_service`] returns the real "access denied"
//!     reason rather than pretending success. To actually stop it the user must
//!     turn Tamper Protection off and run RAM Optimizer elevated.
//!
//! Real implementation on Windows; a no-op (always [`ThreatStatus::Unknown`] /
//! `Err`) everywhere else, so the rest of the crate builds cross-platform.

/// Does this process name belong to the Windows antimalware service?
pub fn is_antimalware(name: &str) -> bool {
    let n = name.to_lowercase();
    n == "msmpeng.exe" || n.contains("antimalware")
}

/// What Defender currently reports about active threats, as far as we could tell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThreatStatus {
    /// Defender reports no active (un-remediated) threats — safe to tame.
    Clear,
    /// Defender reports one or more active threats — leave AV running.
    Present,
    /// Couldn't determine (not Windows, Defender absent, or the query failed).
    Unknown,
}

#[cfg(windows)]
pub fn threats_present() -> ThreatStatus {
    imp::threats_present()
}

/// Attempt to stop the antimalware service(s). `Ok` carries a human-readable note
/// about what the Service Control Manager did; `Err` carries the real failure
/// reason (e.g. Tamper Protection's "access denied").
#[cfg(windows)]
pub fn pause_service() -> Result<String, String> {
    imp::pause_service()
}

/// Is Microsoft Defender **Tamper Protection** on? It blocks stopping `WinDefend`
/// even when elevated — and it **cannot be turned off programmatically** (by
/// design, so malware can't disable AV); only the user can, via Windows Security.
/// `Some(true/false)` from `Get-MpComputerStatus`; `None` if undeterminable.
#[cfg(windows)]
pub fn tamper_protection_on() -> Option<bool> {
    imp::tamper_protection_on()
}

/// One-line, user-facing steps to allow RAM Optimizer to pause Defender. Shown when a
/// stop attempt is blocked, so the user knows exactly what to do by hand.
pub fn pause_howto() -> &'static str {
    "Tamper Protection can't be disabled programmatically. To allow it: open \
     Windows Security ▸ Virus & threat protection ▸ Manage settings ▸ turn OFF \
     Tamper Protection, then run RAM Optimizer elevated (re-register the task with \
     `install-windows.ps1 -Elevated`)."
}

#[cfg(not(windows))]
pub fn threats_present() -> ThreatStatus {
    ThreatStatus::Unknown
}

#[cfg(not(windows))]
pub fn pause_service() -> Result<String, String> {
    Err("antimalware service control is Windows-only".into())
}

#[cfg(not(windows))]
pub fn tamper_protection_on() -> Option<bool> {
    None
}

#[cfg(windows)]
mod imp {
    use super::ThreatStatus;
    use crate::util::hidden_command;
    use std::process::Stdio;

    /// Is Tamper Protection on, per `Get-MpComputerStatus`.IsTamperProtected? One
    /// parseable token, read back. Any error → `None` (caller treats as unknown).
    pub fn tamper_protection_on() -> Option<bool> {
        let script = "try { Write-Output ('RAMOPT_TP=' + [int](Get-MpComputerStatus).IsTamperProtected) } \
                      catch { Write-Output 'RAMOPT_TP=ERR' }";
        let out = hidden_command("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .stdin(Stdio::null())
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(v) = line.trim().strip_prefix("RAMOPT_TP=") {
                return match v.trim() {
                    "1" => Some(true),
                    "0" => Some(false),
                    _ => None,
                };
            }
        }
        None
    }

    /// Ask Defender whether it currently has any **active** threats. `Get-MpThreat`
    /// lists threats Defender knows about; `IsActive` marks the ones not yet fully
    /// remediated. We emit one parseable token and read it back. Any error →
    /// `Unknown` (the caller then leaves the service alone — fail safe).
    pub fn threats_present() -> ThreatStatus {
        let script = "try { $n = @(Get-MpThreat | Where-Object { $_.IsActive }).Count; \
                      Write-Output ('RAMOPT_THREATS=' + $n) } \
                      catch { Write-Output 'RAMOPT_THREATS=ERR' }";
        let out = hidden_command("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .stdin(Stdio::null())
            .output();
        let out = match out {
            Ok(o) => o,
            Err(_) => return ThreatStatus::Unknown,
        };
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(v) = line.trim().strip_prefix("RAMOPT_THREATS=") {
                return match v.trim().parse::<u64>() {
                    Ok(0) => ThreatStatus::Clear,
                    Ok(_) => ThreatStatus::Present,
                    Err(_) => ThreatStatus::Unknown, // "ERR" or unexpected output
                };
            }
        }
        ThreatStatus::Unknown
    }

    /// Stop the antimalware services via the Service Control Manager. Reports the
    /// real outcome — with Tamper Protection on (the default) this returns the
    /// access-denied error rather than a false success.
    pub fn pause_service() -> Result<String, String> {
        // WinDefend = Microsoft Defender Antivirus Service (MsMpEng.exe);
        // WdNisSvc  = its network-inspection helper. WinDefend doesn't accept a
        // PAUSE control, so "pause" maps to a stop.
        let mut notes = Vec::new();
        let mut any_ok = false;
        for svc in ["WinDefend", "WdNisSvc"] {
            match stop_one(svc) {
                Ok(s) => {
                    any_ok = true;
                    notes.push(format!("{svc}: {s}"));
                }
                Err(e) => notes.push(format!("{svc}: {e}")),
            }
        }
        let joined = notes.join("; ");
        if any_ok {
            Ok(joined)
        } else {
            Err(joined)
        }
    }

    fn stop_one(svc: &str) -> Result<String, String> {
        let out = hidden_command("sc.exe")
            .args(["stop", svc])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("could not run sc.exe: {e}"))?;
        // Collapse sc.exe's multi-line status/error block into one tidy line.
        let body = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let oneline = body.split_whitespace().collect::<Vec<_>>().join(" ");
        if out.status.success() {
            Ok(if oneline.is_empty() {
                "stop signal accepted".into()
            } else {
                oneline
            })
        } else {
            // e.g. "[SC] ControlService FAILED 5: Access is denied." (Tamper Protection)
            Err(if oneline.is_empty() {
                format!("sc stop exited with {}", out.status)
            } else {
                oneline
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_antimalware;

    #[test]
    fn matches_defender_process_names() {
        assert!(is_antimalware("MsMpEng.exe"));
        assert!(is_antimalware("msmpeng.exe"));
        assert!(is_antimalware("Antimalware Service Executable"));
        assert!(!is_antimalware("chrome.exe"));
    }
}
