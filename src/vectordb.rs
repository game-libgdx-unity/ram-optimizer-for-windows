//! Upstash Vector (serverless REST, server-side embeddings). Stores each AI
//! escalation as a "strategy" and retrieves similar past incidents to enrich
//! future prompts (RAG). Active only when `vectordb.enabled` is true.
//!
//! Credentials are resolved in this order:
//!   1. `config.json` `vectordb.url` / `vectordb.token`
//!   2. env `UPSTASH_VECTOR_REST_URL` / `UPSTASH_VECTOR_REST_TOKEN`
//!   3. a built-in shared default (below)
//!
//! ── About the built-in default ───────────────────────────────────────────
//! The default URL+token are XOR-obfuscated (not encrypted): the key ships in
//! this binary, so anyone can recover them. Treat them as PUBLIC. They exist so
//! the vector-DB feature works out of the box without each user provisioning
//! their own Upstash index — point `vectordb.url`/`token` (or the env vars) at
//! your own index to opt out of the shared default. The shared default is used
//! for RAG **retrieval only**; writing strategies is disabled on it (see `save`).
use crate::config::Config;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::time::Duration;

// XOR key — must match the one used to generate the blobs below.
const OBF_KEY: &[u8] = b"S3nt1nel::Upstash::Default::v1::xor-obf";
const DEFAULT_URL_OBF: &str =
    "O0caBEJUSkNJUjQCA1kRFg9bSTEWS1lDVUQCFwNCCxcOChFZABBIJkMdAFAdDUJTVQ==";
const DEFAULT_TOKEN_OBF: &str = "EnENMnwmKwNjYh8HPywjHzIIfD4BPiwBIzBjDzt1XU4cNz9VNjU0J1I5QX4jDjZJbgAiHTo0RhlbCRYqMFAjWSBRdwF8fFZOOB9VIjQhO0M6RFUgASpKSwckJToAHhwObRwVFAQgVSFbCRkM";

fn deobf(b64: &str) -> String {
    match STANDARD.decode(b64) {
        Ok(bytes) => bytes
            .iter()
            .enumerate()
            .map(|(i, b)| (b ^ OBF_KEY[i % OBF_KEY.len()]) as char)
            .collect(),
        Err(_) => String::new(),
    }
}

/// `(url, token)` from config → env → built-in default.
fn creds(cfg: &Config) -> (String, String) {
    let url = if !cfg.vectordb.url.trim().is_empty() {
        cfg.vectordb.url.trim().to_string()
    } else if let Ok(u) = std::env::var("UPSTASH_VECTOR_REST_URL") {
        u
    } else {
        deobf(DEFAULT_URL_OBF)
    };
    let token = if !cfg.vectordb.token.trim().is_empty() {
        cfg.vectordb.token.trim().to_string()
    } else if let Ok(t) = std::env::var("UPSTASH_VECTOR_REST_TOKEN") {
        t
    } else {
        deobf(DEFAULT_TOKEN_OBF)
    };
    (url, token)
}

/// True when the feature is switched on (credentials always resolve, via the
/// built-in default if the user supplied none).
pub fn enabled(cfg: &Config) -> bool {
    cfg.vectordb.enabled && {
        let (u, t) = creds(cfg);
        !u.is_empty() && !t.is_empty()
    }
}

/// `true` when the active credentials are the built-in shared default (the user
/// supplied neither config nor env). The UI surfaces this so it's never a secret.
pub fn using_builtin_default(cfg: &Config) -> bool {
    cfg.vectordb.url.trim().is_empty()
        && cfg.vectordb.token.trim().is_empty()
        && std::env::var("UPSTASH_VECTOR_REST_URL").is_err()
}

fn post(cfg: &Config, path_name: &str, body: Value) -> Option<Value> {
    let (url, token) = creds(cfg);
    let full = format!("{}{}", url.trim_end_matches('/'), path_name);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .ok()?;
    let res = client
        .post(&full)
        .bearer_auth(&token)
        .json(&body)
        .send()
        .ok()?;
    if !res.status().is_success() {
        return None;
    }
    res.json::<Value>().ok()
}

/// Retrieve up to topK past incidents similar to `text`.
pub fn query(cfg: &Config, text: &str) -> Vec<Value> {
    if !enabled(cfg) || text.is_empty() {
        return vec![];
    }
    let top_k = if cfg.vectordb.top_k > 0 {
        cfg.vectordb.top_k
    } else {
        3
    };
    let body = json!({ "data": text, "topK": top_k, "includeMetadata": true });
    match post(cfg, "/query-data", body) {
        Some(j) => j["result"].as_array().cloned().unwrap_or_default(),
        None => vec![],
    }
}

/// Save one incident/strategy. `id` should be unique; `text` is embedded for
/// later similarity search.
///
/// The built-in shared default index is **read-only**: we never write to it
/// (that would let any user poison a public, maintainer-owned index and would
/// leak hostnames into it). Strategies only persist to *your own* configured
/// index — set `vectordb.url`/`token` or the env vars to enable writing.
pub fn save(cfg: &Config, id: &str, text: &str, metadata: Value) -> bool {
    if !enabled(cfg) || text.is_empty() || using_builtin_default(cfg) {
        return false;
    }
    let mut md = metadata;
    if let Some(obj) = md.as_object_mut() {
        obj.insert("host".into(), json!(hostname()));
    }
    let body = json!({ "id": id, "data": text, "metadata": md });
    match post(cfg, "/upsert-data", body) {
        Some(j) => {
            let r = &j["result"];
            r.as_str().map(|s| !s.is_empty()).unwrap_or(!r.is_null())
        }
        None => false,
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards against a corrupted/mis-encoded built-in blob (no network).
    #[test]
    fn builtin_default_decodes() {
        let url = deobf(DEFAULT_URL_OBF);
        let tok = deobf(DEFAULT_TOKEN_OBF);
        assert!(
            url.starts_with("https://") && url.contains("upstash.io"),
            "url={url}"
        );
        assert!(tok.len() > 40, "token looked too short");
    }
}
