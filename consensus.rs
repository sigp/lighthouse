// consensus.rs
// Module for interacting with Lighthouse consensus events, sync checkpoints, and authorship claims

use chrono::Utc;
use std::fs::OpenOptions;
use std::io::Write;

/// Struct representing a notarized consensus snapshot
#[derive(Debug)]
pub struct ConsensusSnapshot {
    pub timestamp: String,
    pub slot: u64,
    pub finalized: bool,
    pub pubkey: String,
    pub otp_proof: Option<String>,
}

/// Log consensus snapshot to disk for timestamping and IPFS feed
pub fn log_consensus(snapshot: &ConsensusSnapshot) {
    let json = format!(
        "{{\"timestamp\":\"{}\",\"slot\":{},\"finalized\":{},\"pubkey\":\"{}\",\"otp_proof\":\"{}\"}}\n",
        snapshot.timestamp,
        snapshot.slot,
        snapshot.finalized,
        snapshot.pubkey,
        snapshot.otp_proof.clone().unwrap_or("null".to_string())
    );

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("consensus_snapshots.json")
        .expect("Failed to open consensus snapshot log");

    file.write_all(json.as_bytes())
        .expect("Failed to write snapshot log");

    println!("✅ Logged consensus snapshot for slot {}", snapshot.slot);
}

/// Create a new snapshot from raw inputs
pub fn build_snapshot(slot: u64, finalized: bool, pubkey: &str, otp_proof: Option<String>) -> ConsensusSnapshot {
    ConsensusSnapshot {
        timestamp: Utc::now().to_rfc3339(),
        slot,
        finalized,
        pubkey: pubkey.to_string(),
        otp_proof,
    }
}ots stamp consensus_snapshots.json
ipfs add consensus_snapshots.json

