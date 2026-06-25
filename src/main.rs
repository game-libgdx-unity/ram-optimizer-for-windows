//! ram-optimizer — lightweight cross-platform process/RAM/CPU monitor.
//!
//! Usage:
//!   ram-optimizer                  open the desktop dashboard + auto-start the
//!                             background schedule (what double-clicking does)
//!   ram-optimizer ui | serve       same — the native desktop dashboard
//!   ram-optimizer --once           one headless monitoring pass (what the OS
//!                             scheduler runs every interval; no window)
//!   ram-optimizer --once --print   ...and print findings to stdout
//!   ram-optimizer --once --no-act  ...and never kill/restart (monitor only)
//!   ram-optimizer --dump           list top processes with command lines (debug)
//!
//! The default is the dashboard so the app is friendly to launch; the headless
//! one-shot is gated behind `--once` (or `--print`/`--no-act`/`--dump`) so the
//! scheduled task — which passes `--once` — never pops a window.
//!
//!   ram-optimizer --tray           open the dashboard hidden (tray icon only — used
//!                             by the optional launch-at-login entry)
//
// Build as a Windows GUI app (subsystem:windows) so launching the binary never
// spawns a console window — we want only the taskbar + tray icon. The trade-off
// is that `--print`/`--dump` won't echo to a terminal on Windows (they still run;
// the scheduled `--once` logs to ~/.ram-optimizer/cron.log regardless). No effect on
// macOS/Linux.
#![cfg_attr(windows, windows_subsystem = "windows")]
mod actions;
mod ai;
mod alert;
mod collect;
mod config;
mod critical;
mod detect;
mod guard;
mod optimize;
mod pass;
mod rules;
mod runlog;
mod scheduler;
mod single;
mod state;
mod tray;
mod ui;
mod util;
mod vectordb;
mod windefend;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let print = args.iter().any(|a| a == "--print");
    let no_act = args.iter().any(|a| a == "--no-act" || a == "--dry-run");
    let dump = args.iter().any(|a| a == "--dump");
    let once = args
        .iter()
        .any(|a| a == "--once" || a == "scan" || a == "run");
    let explicit_ui = args.iter().any(|a| a == "ui" || a == "serve");
    // Start the dashboard hidden (tray icon only) — for the launch-at-login entry.
    let tray_only = args
        .iter()
        .any(|a| a == "--tray" || a == "--hidden" || a == "--minimized");
    // Explicitly surface the window (e.g. `ram-optimizer --show` from a shortcut).
    let want_show = args.iter().any(|a| a == "--show");

    let cfg = config::load_config();

    // Default action (bare exe / double-click) is the dashboard. A headless pass
    // runs only when explicitly asked for — the OS scheduler invokes `--once`, so
    // the scheduled task never opens a window.
    let headless = once || print || no_act || dump;
    if explicit_ui || tray_only || want_show || !headless {
        // One UI instance only (so there's a single tray icon). If another is
        // already running, exit silently — we NEVER auto-pop the window. Only an
        // explicit `--show` asks the running instance to surface itself.
        if !single::acquire() {
            // A foreground launch (double-click / `ram-optimizer ui` / `--show`) means
            // "open it" → surface the already-running instance. Only a background
            // `--tray` relaunch stays silent, so the app never auto-pops on its own.
            if !tray_only {
                single::signal_show();
            }
            return;
        }
        // Only `--tray` (the launch-at-login entry) starts hidden. A double-click
        // opens the window normally. `ui.startHidden` can opt the bare launch into
        // hidden too, but a foreground `--show` / `ram-optimizer ui` always wins.
        let start_hidden = tray_only || (!want_show && !explicit_ui && cfg.ui.start_hidden);
        ui::run(start_hidden);
        return;
    }

    if dump {
        let snap = collect::collect();
        let mut procs: Vec<_> = snap.procs.iter().collect();
        procs.sort_by_key(|p| std::cmp::Reverse(p.mem_mb));
        println!(
            "{} procs, RAM {:.0}% ({}/{} MB). Top 30 by memory:",
            snap.procs.len(),
            snap.used_pct,
            snap.used_mb,
            snap.total_mb
        );
        for p in procs.into_iter().take(30) {
            println!(
                "  pid={:<7} {:<24} {:>6} MB  {:>5.0}%  {}",
                p.pid, p.name, p.mem_mb, p.cpu, p.exe
            );
        }
        return;
    }

    let rec = pass::run_pass(&cfg, &pass::PassOpts::scheduled(!no_act));

    if print {
        if rec.findings.is_empty() {
            println!(
                "RAM {:.0}% ({}/{} MB) — no anomalies.",
                rec.ram_before_pct, rec.ram_before_mb, rec.total_mb
            );
        } else {
            println!(
                "RAM {:.0}% ({}/{} MB) — {} finding(s) in {} ms:",
                rec.ram_before_pct,
                rec.ram_before_mb,
                rec.total_mb,
                rec.findings.len(),
                rec.duration_ms
            );
            for f in &rec.findings {
                println!("  [{}] {} — {}", f.kind, f.title, f.detail);
            }
            if let Some(ai) = &rec.ai {
                if !ai.advice.is_empty() {
                    println!("  AI advice: {}", ai.advice);
                }
            }
        }
        if no_act {
            println!("  optimizer: skipped (--no-act)");
        } else if rec.reclaimed_mb > 0 {
            println!(
                "  optimizer: reclaimed ~{} MB ({:.2}% of RAM)",
                rec.reclaimed_mb, rec.reduced_pct
            );
        } else {
            println!("  optimizer: no actions");
        }
        for a in &rec.actions {
            println!("  action: {}", a);
        }
    }
}
