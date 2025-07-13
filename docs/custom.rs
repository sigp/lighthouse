// custom.rs
// Experimental validator logic for authorship tracking and sync notarization

use chrono::Utc;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;

/// Log sync distance to a JSON file with timestamp and validator pubkey
pub fn log_sync(distance: u64, pubkey: &str) {
    let timestamp = Utc::now().to_rfc3339();
    let json_entry = format!(
        "{{\"timestamp\":\"{}\",\"sync_distance\":{},\"validator_pubkey\":\"{}\"}}\n",
        timestamp, distance, pubkey
    );

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("beacon_sync_log.json")
        .expect("Failed to open log file");

    file.write_all(json_entry.as_bytes())
        .expect("Failed to write log entry");
}

/// Run OpenTimestamps CLI to notarize the sync log
pub fn notarize_latest_log() {
    let status = Command::new("ots")
        .arg("stamp")
        .arg("beacon_sync_log.json")
        .status()
        .expect("Failed to execute OpenTimestamps");

    if status.success() {
        println!("✅ Sync log successfully timestamped");
    } else {
