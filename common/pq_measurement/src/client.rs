//! Shared BN/VC configuration. Deployment identity is independent of process identity.
use crate::{Config, Recorder, install_global};
use serde_json::json;
use std::time::Duration;

pub fn node_id(explicit: Option<&str>) -> Result<String, String> {
    let value=explicit.map(str::to_owned).or_else(||std::env::var("PQ_MEASUREMENT_NODE_ID").ok())
        .ok_or("PQ measurements require --pq-measurement-node-id or PQ_MEASUREMENT_NODE_ID; use the same logical node ID for its BN and VC")?;
    if value.trim().is_empty() || value.len() > 256 {
        return Err("PQ measurement node ID must contain 1 to 256 bytes".into());
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub fn start(
    endpoint: &str,
    node_id: &str,
    role: &str,
    network: &str,
    genesis_root: String,
    genesis_time: u64,
    slot_duration: Duration,
    client_commit: &str,
    prover: Option<(&str, Option<usize>)>,
) -> Result<(), String> {
    let bn = role == "bn";
    let mut data = json!({
        "network":network,"genesis_root":genesis_root,"genesis_unix_ns":Duration::from_secs(genesis_time).as_nanos().to_string(),
        "slot_ns":slot_duration.as_nanos().to_string(),"client_commit":if client_commit.is_empty(){"unavailable"}else{client_commit},
        "hardware_ref":std::env::var("PQ_MEASUREMENT_HARDWARE_REF").unwrap_or_else(|_|"unavailable:CPU model, allocation, quota, affinity, memory limit and execution environment; deployment must supply host metadata".into()),
        "metrics_node_ref":format!("deployment:{node_id}"),"schedule_ref":"per-duty collection/broadcast/proposal timestamps",
        "gossip_id_algorithm":"ethereum-altair:sha256(domain4||topic_len_le_u64||topic||uncompressed_ssz)[0..20]",
        "instrumentation_revision":"lighthouse-pq.measurement/0.1-traffic1 (spec 1effe59); traffic nominal UTC boundaries use fixed observer-start paired anchor; no wall-step reanchor",
        "hooks":{
            "receipt":{"code_location":if bn{"lighthouse_network::service::inject_gs_event before SSZ decode"}else{"not_exposed: validator client has no gossip stack"},"decompression":"before","deduplication":"before"},
            "validation_start":if bn{"network_beacon_processor::process_gossip_aggregate and per-item PQ batch callback"}else{"not_exposed"},
            "validation_finish":if bn{"aggregate verifier returns, before fork-choice and proposal pool insertion"}else{"not_exposed"},
            "usable":if bn{"BeaconChain::add_to_block_inclusion_pool_with_origin after production op_pool.insert_pq_attestation"}else{"not_exposed"},
            "publish":if bn{"lighthouse_network::Service::publish immediately around existing libp2p publish invocation"}else{"not_exposed: HTTP submission is not network publication"},
            "backend_start":if bn{"pq_prover::in_process::aggregate immediately before lean_vm::aggregate"}else{"not_exposed: aggregation backend is in BN"},
            "backend_finish":if bn{"pq_prover::in_process::aggregate immediately after lean_vm::aggregate returns"}else{"not_exposed"},
            "backend_scope":"one synchronous lean_vm::aggregate call; native internal lock waiting included; child decoding, caller gathering, output serialization and final policy checks excluded; fixed native inputs admitted on existing blocking worker; no additional queue introduced",
            "caller_scope":if bn{"not_exposed; submission counters unavailable for Tokio blocking executor; aggregate traffic: compressed decoded copies including invalid entries before filtering, TX successful per-peer queue insertion; full scopes in traffic records; no NIC bytes or whole-frame predecode failures"}else{"not_exposed; validator client has no gossip stack"},
            "proof_verify_scope":"not_exposed"
        },"unavailable":[]
    });
    let mut unavailable = vec![];
    if let Some((revision, threads)) = prover {
        data["prover_revision"] = json!(revision);
        data["proof_parameters"] = json!({"log_inv_rate":2,"backend":"leanvm-in-process"});
        if let Some(threads) = threads.filter(|n| *n > 0) {
            data["effective_prover_threads"] = json!(threads);
        } else {
            unavailable.push("effective_prover_threads");
        }
    } else {
        unavailable.extend([
            "prover_revision",
            "proof_parameters",
            "effective_prover_threads",
        ]);
    }
    data["unavailable"] = json!(unavailable);
    let config = Config::new(endpoint, node_id, format!("lighthouse-{role}"), data)?;
    let recorder = Recorder::start(config)?;
    install_global(recorder)
        .map_err(|_| "PQ measurement recorder already initialized in this process".into())
}
