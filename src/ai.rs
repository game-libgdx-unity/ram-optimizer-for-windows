//! AI escalation for unrecognized findings. Default provider = OpenAI;
//! switchable to Groq or the local `claude` CLI, with fallback (via reqwest).
//! Rate-limited. RAG context
//! pulled from the vector DB; each escalation is persisted back as a "strategy"
//! for next time.
//!
//! `maybe_escalate` is what the scheduled pass calls (respects the rate limit).
//! `force_escalate` / `build_prompt_text` back the dashboard's "Ask AI" button,
//! which works on demand for complex/abnormal cases.
use crate::config::Config;
use crate::detect::Finding;
use crate::runlog::{AiRec, StrategyRec};
use crate::state::Meta;
use crate::util::{hidden_command, now_epoch};
use crate::vectordb;
use serde_json::{json, Value};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// What one escalation produced — surfaced in the run record + action log.
pub struct AiOutcome {
    pub rec: AiRec,
    pub strategies: Vec<StrategyRec>,
}

/// Findings worth escalating: the unrecognized/abnormal ones, or all of them
/// if none are explicitly novel (so the "Ask AI" button is never empty-handed).
fn escalation_targets(findings: &[Finding]) -> Vec<&Finding> {
    let novel: Vec<&Finding> = findings.iter().filter(|f| !f.recognized).collect();
    if novel.is_empty() {
        findings.iter().collect()
    } else {
        novel
    }
}

/// Scheduled-pass escalation: honors `ai.enabled` and the inter-escalation gap.
pub fn maybe_escalate(findings: &[Finding], cfg: &Config, meta: &mut Meta) -> Option<AiOutcome> {
    if !cfg.ai.enabled || findings.iter().all(|f| f.recognized) {
        return None;
    }
    let now = now_epoch();
    let mins = if cfg.ai.min_minutes_between_escalations == 0 {
        60
    } else {
        cfg.ai.min_minutes_between_escalations
    };
    if now.saturating_sub(meta.last_escalation_epoch) < mins.saturating_mul(60) {
        return None;
    }
    let out = run_escalation(findings, cfg)?;
    meta.last_escalation_epoch = now;
    Some(out)
}

/// On-demand escalation (dashboard button): honors `ai.enabled` but ignores the
/// rate limit. Returns None if AI is off or every provider failed.
pub fn force_escalate(findings: &[Finding], cfg: &Config) -> Option<AiOutcome> {
    if !cfg.ai.enabled {
        return None;
    }
    run_escalation(findings, cfg)
}

/// Build the exact prompt that would be sent (with RAG context), without calling
/// any provider. Lets the UI show a copy-pasteable prompt even when AI is off.
pub fn build_prompt_text(findings: &[Finding], cfg: &Config) -> String {
    let targets = escalation_targets(findings);
    let anomaly_text = targets
        .iter()
        .map(|f| format!("[{}] {} — {}", f.kind, f.title, f.detail))
        .collect::<Vec<_>>()
        .join("\n");
    let past = vectordb::query(cfg, &anomaly_text);
    build_prompt(&targets, &past)
}

fn run_escalation(findings: &[Finding], cfg: &Config) -> Option<AiOutcome> {
    let targets = escalation_targets(findings);
    if targets.is_empty() {
        return None;
    }
    let anomaly_text = targets
        .iter()
        .map(|f| format!("[{}] {} — {}", f.kind, f.title, f.detail))
        .collect::<Vec<_>>()
        .join("\n");

    // RAG: retrieve similar past incidents to give the model prior context.
    let past = vectordb::query(cfg, &anomaly_text);
    let prompt = build_prompt(&targets, &past);

    for provider in provider_order(cfg) {
        if let Some(ans) = call_provider(&provider, &prompt, cfg) {
            let advice = ans.trim().to_string();
            if !advice.is_empty() {
                let now = now_epoch();
                let strategies = save_incidents(cfg, &targets, &advice, &provider, now);
                let rec = AiRec {
                    provider: provider.clone(),
                    model: model_name(&provider, cfg),
                    prompt_chars: prompt.chars().count(),
                    prompt,
                    advice,
                };
                return Some(AiOutcome { rec, strategies });
            }
        }
    }
    None
}

fn model_name(provider: &str, cfg: &Config) -> String {
    match provider {
        "groq" => cfg.ai.groq_model.clone(),
        "openai" => cfg.ai.openai_model.clone(),
        "claude" => "claude (local CLI)".into(),
        other => other.into(),
    }
}

fn save_incidents(
    cfg: &Config,
    targets: &[&Finding],
    advice: &str,
    provider: &str,
    now: u64,
) -> Vec<StrategyRec> {
    let mut saved = Vec::new();
    if !vectordb::enabled(cfg) {
        return saved;
    }
    for (i, f) in targets.iter().enumerate() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let id = format!("{}-{}-{}", now, i, nanos);
        let text = format!("[{}] {} — {}", f.kind, f.title, f.detail);
        let md = json!({
            "kind": f.kind, "title": f.title, "detail": f.detail,
            "advice": advice, "provider": provider, "ts": now,
        });
        if vectordb::save(cfg, &id, &text, md) {
            saved.push(StrategyRec { id, text });
        }
    }
    saved
}

fn provider_order(cfg: &Config) -> Vec<String> {
    let mut v = vec![cfg.ai.provider.clone()];
    for f in &cfg.ai.fallback {
        if !v.contains(f) {
            v.push(f.clone());
        }
    }
    v
}

fn build_prompt(targets: &[&Finding], past: &[Value]) -> String {
    let mut s = String::from(
        "You are a Windows/macOS/Linux system-health assistant. Below are anomalies a \
         lightweight monitor detected on the user's machine. For each, in ONE short line, say \
         whether it is likely benign or a real problem and the single best action. Be concise \
         and concrete. Do not ask questions.\n\n",
    );

    if !past.is_empty() {
        s.push_str(
            "Similar past incidents on this machine and the advice given then \
             (use as context, do not just repeat):\n",
        );
        for p in past {
            let m = &p["metadata"];
            let title = m["title"]
                .as_str()
                .or_else(|| m["kind"].as_str())
                .unwrap_or("incident");
            let advice = m["advice"].as_str().unwrap_or("");
            let score = match p["score"].as_f64() {
                Some(v) => format!(" (sim {:.2})", v),
                None => String::new(),
            };
            s.push_str(&format!("- {}{}: {}\n", title, score, advice));
        }
        s.push('\n');
    }

    s.push_str("Current anomalies:\n");
    for f in targets {
        s.push_str(&format!("- [{}] {} — {}\n", f.kind, f.title, f.detail));
    }
    s
}

fn call_provider(provider: &str, prompt: &str, cfg: &Config) -> Option<String> {
    match provider {
        "claude" => call_claude(prompt),
        "groq" => call_openai_compatible(
            "https://api.groq.com/openai/v1/chat/completions",
            &cfg.ai.groq_api_key,
            &cfg.ai.groq_model,
            prompt,
        ),
        "openai" => call_openai_compatible(
            "https://api.openai.com/v1/chat/completions",
            &cfg.ai.openai_api_key,
            &cfg.ai.openai_model,
            prompt,
        ),
        _ => None,
    }
}

/// Local Claude Code CLI in headless print mode, with a 60s hard timeout.
///
/// The prompt is fed on stdin (not as an argv), which dodges shell-quoting of
/// multi-line prompts. On Windows we go through `cmd /C` so the `claude.cmd`
/// npm shim is resolved via PATHEXT (a bare `Command::new("claude")` only finds
/// `claude.exe`, which the npm install does not provide).
fn call_claude(prompt: &str) -> Option<String> {
    use std::io::{Read, Write};
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::thread;

    #[cfg(windows)]
    let mut cmd = {
        let mut c = hidden_command("cmd");
        c.args(["/C", "claude", "-p"]);
        c
    };
    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = hidden_command("claude");
        c.arg("-p");
        c
    };

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Feed the prompt, then close stdin (EOF) before reading stdout.
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(prompt.as_bytes());
    }

    let mut stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        let _ = tx.send(s);
    });

    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(s) => {
            let _ = child.wait();
            let t = s.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

fn call_openai_compatible(url: &str, key: &str, model: &str, prompt: &str) -> Option<String> {
    if key.trim().is_empty() {
        return None;
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .ok()?;
    let body = json!({
        "model": model,
        "messages": [{ "role": "user", "content": prompt }],
        "temperature": 0.2,
        "max_tokens": 300,
    });
    let res = client.post(url).bearer_auth(key).json(&body).send().ok()?;
    if !res.status().is_success() {
        return None;
    }
    let j: Value = res.json().ok()?;
    j["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
}
