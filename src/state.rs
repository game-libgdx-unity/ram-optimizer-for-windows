//! Cross-run state: the previous snapshot (for CPU trends) and rate-limit meta.
//! Stored as JSON in ~/.ram-optimizer, field names matching the JS format.
use crate::collect::Snapshot;
use crate::config::state_dir;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default, rename_all = "camelCase")]
pub struct Meta {
    pub last_escalation_epoch: u64,
    pub last_alert_epoch: u64,
    pub last_kinds: Vec<String>,
    /// Consecutive passes system RAM has stayed at/above the aggressive gate.
    /// Drives the aggressive tier's hysteresis (see `optimize::run`): the
    /// no-confirmation kill waits until this reaches `autoActConfirmPasses`,
    /// so a single transient spike never triggers it. Reset to 0 once RAM drops.
    pub aggressive_streak: u32,
}

fn snap_path() -> PathBuf {
    state_dir().join("snapshot.json")
}
fn meta_path() -> PathBuf {
    state_dir().join("meta.json")
}

pub fn load_prev() -> Option<Snapshot> {
    let s = std::fs::read_to_string(snap_path()).ok()?;
    serde_json::from_str(&s).ok()
}

pub fn save_snapshot(s: &Snapshot) {
    if let Ok(txt) = serde_json::to_string(s) {
        let _ = std::fs::write(snap_path(), txt);
    }
}

pub fn load_meta() -> Meta {
    match std::fs::read_to_string(meta_path()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Meta::default(),
    }
}

pub fn save_meta(m: &Meta) {
    if let Ok(txt) = serde_json::to_string(m) {
        let _ = std::fs::write(meta_path(), txt);
    }
}
