use crate::local_network::LocalNetwork;
use node_test_rig::eth2::types::{BlockId, FinalityCheckpointsData, StateId};
use std::time::Duration;
use types::{Epoch, EthSpec, ExecPayload, ExecutionBlockHash, Slot, Unsigned};

/// Checks that all of the validators have on-boarded by the start of the second eth1 voting
/// period.
pub async fn verify_initial_validator_count<E: EthSpec>(
    network: LocalNetwork<E>,
    slot_duration: Duration,
    initial_validator_count: usize,
) -> Result<(), String> {
    slot_delay(Slot::new(1), slot_duration).await;
    verify_validator_count(network, initial_validator_count).await?;
    Ok(())
}

/// Checks that all of the validators have on-boarded by the start of the second eth1 voting
/// period.
pub async fn verify_validator_onboarding<E: EthSpec>(
    network: LocalNetwork<E>,
    slot_duration: Duration,
    expected_validator_count: usize,
) -> Result<(), String> {
    slot_delay(
        Slot::new(E::SlotsPerEth1VotingPeriod::to_u64()),
        slot_duration,
    )
    .await;
    verify_validator_count(network, expected_validator_count).await?;
    Ok(())
}

/// Checks that the chain has made the first possible finalization.
///
/// Intended to be run as soon as chain starts.
pub async fn verify_first_finalization<E: EthSpec>(
    network: LocalNetwork<E>,
    slot_duration: Duration,
) -> Result<(), String> {
    epoch_delay(Epoch::new(4), slot_duration, E::slots_per_epoch()).await;
    verify_all_finalized_at(network, Epoch::new(2)).await?;
    Ok(())
}

/// Delays for `epochs`, plus half a slot extra.
pub async fn epoch_delay(epochs: Epoch, slot_duration: Duration, slots_per_epoch: u64) {
    let duration = slot_duration * (epochs.as_u64() * slots_per_epoch) as u32 + slot_duration / 2;
    tokio::time::sleep(duration).await
}

/// Delays for `slots`, plus half a slot extra.
async fn slot_delay(slots: Slot, slot_duration: Duration) {
    let duration = slot_duration * slots.as_u64() as u32 + slot_duration / 2;
    tokio::time::sleep(duration).await;
}

/// Verifies that all beacon nodes in the given network have a head state that has a finalized
/// epoch of `epoch`.
pub async fn verify_all_finalized_at<E: EthSpec>(
    network: LocalNetwork<E>,
    epoch: Epoch,
) -> Result<(), String> {
    let epochs = {
        let mut epochs = Vec::new();
        for remote_node in network.remote_nodes()? {
            epochs.push(
                remote_node
                    .get_beacon_states_finality_checkpoints(StateId::Head)
                    .await
                    .map(|body| body.unwrap().data.finalized.epoch)
                    .map_err(|e| format!("Get head via http failed: {:?}", e))?,
            );
        }
        epochs
    };

    if epochs.iter().any(|node_epoch| *node_epoch != epoch) {
        Err(format!(
            "Nodes are not finalized at epoch {}. Finalized epochs: {:?}",
            epoch, epochs
        ))
    } else {
        Ok(())
    }
}

/// Verifies that all beacon nodes in the given `network` have a head state that contains
/// `expected_count` validators.
async fn verify_validator_count<E: EthSpec>(
    network: LocalNetwork<E>,
    expected_count: usize,
) -> Result<(), String> {
    let validator_counts = {
        let mut validator_counts = Vec::new();
        for remote_node in network.remote_nodes()? {
            let vc = remote_node
                .get_debug_beacon_states::<E>(StateId::Head)
                .await
                .map(|body| body.unwrap().data)
                .map_err(|e| format!("Get state root via http failed: {:?}", e))?
                .validators()
                .len();
            validator_counts.push(vc);
        }
        validator_counts
    };

    if validator_counts
        .iter()
        .any(|count| *count != expected_count)
    {
        Err(format!(
            "Nodes do not all have {} validators in their state. Validator counts: {:?}",
            expected_count, validator_counts
        ))
    } else {
        Ok(())
    }
}

/// Verifies that there's been a block produced at every slot up to and including `slot`.
pub async fn verify_full_block_production_up_to<E: EthSpec>(
    network: LocalNetwork<E>,
    slot: Slot,
    slot_duration: Duration,
) -> Result<(), String> {
    slot_delay(slot, slot_duration).await;
    let beacon_nodes = network.beacon_nodes.read();
    let beacon_chain = beacon_nodes[0].client.beacon_chain().unwrap();
    let num_blocks = beacon_chain
        .chain_dump()
        .unwrap()
        .iter()
        .take_while(|s| s.beacon_block.slot() <= slot)
        .count();
    if num_blocks != slot.as_usize() + 1 {
        return Err(format!(
            "There wasn't a block produced at every slot, got: {}, expected: {}",
            num_blocks,
            slot.as_usize() + 1
        ));
    }
    Ok(())
}

/// Verify that all nodes have the correct fork version after the `fork_epoch`.
pub async fn verify_fork_version<E: EthSpec>(
    network: LocalNetwork<E>,
    fork_epoch: Epoch,
    slot_duration: Duration,
    fork_version: [u8; 4],
) -> Result<(), String> {
    epoch_delay(fork_epoch, slot_duration, E::slots_per_epoch()).await;
    for remote_node in network.remote_nodes()? {
        let remote_fork_version = remote_node
            .get_beacon_states_fork(StateId::Head)
            .await
            .map(|resp| resp.unwrap().data.current_version)
            .map_err(|e| format!("Failed to get fork from beacon node: {:?}", e))?;
        if fork_version != remote_fork_version {
            return Err(format!(
                "Fork version after FORK_EPOCH is incorrect, got: {:?}, expected: {:?}",
                remote_fork_version, fork_version,
            ));
        }
    }
    Ok(())
}

/// Verify that all sync aggregates from `sync_committee_start_slot` until `upto_slot`
/// have full aggregates.
pub async fn verify_full_sync_aggregates_up_to<E: EthSpec>(
    network: LocalNetwork<E>,
    sync_committee_start_slot: Slot,
    upto_slot: Slot,
    slot_duration: Duration,
) -> Result<(), String> {
    slot_delay(upto_slot, slot_duration).await;
    let remote_nodes = network.remote_nodes()?;
    let remote_node = remote_nodes.first().unwrap();

    for slot in sync_committee_start_slot.as_u64()..=upto_slot.as_u64() {
        let sync_aggregate_count = remote_node
            .get_beacon_blocks::<E>(BlockId::Slot(Slot::new(slot)))
            .await
            .map(|resp| {
                resp.unwrap()
                    .data
                    .message()
                    .body()
                    .sync_aggregate()
                    .map(|agg| agg.num_set_bits())
            })
            .map_err(|e| format!("Error while getting beacon block: {:?}", e))?
            .map_err(|_| format!("Altair block {} should have sync aggregate", slot))?;

        if sync_aggregate_count != E::sync_committee_size() {
            return Err(format!(
                "Sync aggregate at slot {} was not full, got: {}, expected: {}",
                slot,
                sync_aggregate_count,
                E::sync_committee_size()
            ));
        }
    }

    Ok(())
}

/// Verify that the first merged PoS block got finalized.
pub async fn verify_transition_block_finalized<E: EthSpec>(
    network: LocalNetwork<E>,
    transition_epoch: Epoch,
    slot_duration: Duration,
    should_verify: bool,
) -> Result<(), String> {
    if !should_verify {
        return Ok(());
    }
    epoch_delay(transition_epoch + 2, slot_duration, E::slots_per_epoch()).await;
    let mut block_hashes = Vec::new();
    for remote_node in network.remote_nodes()?.iter() {
        let execution_block_hash: ExecutionBlockHash = remote_node
            .get_beacon_blocks::<E>(BlockId::Finalized)
            .await
            .map(|body| body.unwrap().data)
            .map_err(|e| format!("Get state root via http failed: {:?}", e))?
            .message()
            .execution_payload()
            .map(|payload| payload.block_hash())
            .map_err(|e| format!("Execution payload does not exist: {:?}", e))?;
        block_hashes.push(execution_block_hash);
    }

    let first = block_hashes[0];
    if block_hashes.iter().all(|&item| item == first) {
        Ok(())
    } else {
        Err(format!(
            "Terminal block not finalized on all nodes Finalized block hashes:{:?}",
            block_hashes
        ))
    }
}

pub(crate) async fn verify_light_client_updates<E: EthSpec>(
    network: LocalNetwork<E>,
    start_slot: Slot,
    end_slot: Slot,
    slot_duration: Duration,
) -> Result<(), String> {
    slot_delay(start_slot, slot_duration).await;

    // Tolerance of 2 slot allows for 1 single missed slot.
    let light_client_update_slot_tolerance = Slot::new(2);
    let remote_nodes = network.remote_nodes()?;
    let client = remote_nodes.first().unwrap();
    let mut have_seen_block = false;
    let mut have_achieved_finality = false;

    for slot in start_slot.as_u64()..=end_slot.as_u64() {
        slot_delay(Slot::new(1), slot_duration).await;
        let slot = Slot::new(slot);
        let previous_slot = slot - 1;

        let previous_slot_block = client
            .get_beacon_blocks::<E>(BlockId::Slot(previous_slot))
            .await
            .map_err(|e| {
                format!("Unable to get beacon block for previous slot {previous_slot:?}: {e:?}")
            })?;
        let previous_slot_has_block = previous_slot_block.is_some();

        if !have_seen_block {
            // Make sure we have seen the first block in Altair, to make sure we have sync aggregates available.
            if previous_slot_has_block {
                have_seen_block = true;
            }
            // Wait for another slot before we check the first update to avoid race condition.
            continue;
        }

        // Make sure previous slot has a block, otherwise skip checking for the signature slot distance
        if !previous_slot_has_block {
            continue;
        }

        // Verify light client optimistic update. `signature_slot_distance` should be 1 in the ideal scenario.
        let signature_slot = *client
            .get_beacon_light_client_optimistic_update::<E>()
            .await
            .map_err(|e| format!("Error while getting light client updates: {:?}", e))?
            .ok_or(format!("Light client optimistic update not found {slot:?}"))?
            .data
            .signature_slot();
        let signature_slot_distance = slot - signature_slot;
        if signature_slot_distance > light_client_update_slot_tolerance {
            return Err(format!("Existing optimistic update too old: signature slot {signature_slot}, current slot {slot:?}"));
        }

        // Verify light client finality update. `signature_slot_distance` should be 1 in the ideal scenario.
        // NOTE: Currently finality updates are produced as long as the finalized block is known, even if the finalized header
        // sync committee period does not match the signature slot committee period.
        // TODO: This complies with the current spec, but we should check if this is a bug.
        if !have_achieved_finality {
            let FinalityCheckpointsData { finalized, .. } = client
                .get_beacon_states_finality_checkpoints(StateId::Head)
                .await
                .map_err(|e| format!("Unable to get beacon state finality checkpoint: {e:?}"))?
                .ok_or("Unable to get head state".to_string())?
                .data;
            if !finalized.root.is_zero() {
                // Wait for another slot before we check the first finality update to avoid race condition.
                have_achieved_finality = true;
            }
            continue;
        }
        let signature_slot = *client
            .get_beacon_light_client_finality_update::<E>()
            .await
            .map_err(|e| format!("Error while getting light client updates: {:?}", e))?
            .ok_or(format!("Light client finality update not found {slot:?}"))?
            .data
            .signature_slot();
        let signature_slot_distance = slot - signature_slot;
        if signature_slot_distance > light_client_update_slot_tolerance {
            return Err(format!(
                "Existing finality update too old: signature slot {signature_slot}, current slot {slot:?}"
            ));
        }
    }

    Ok(())
}

/// Checks that a node is synced with the network.
/// Useful for ensuring that a node which started after genesis is able to sync to the head.
pub async fn ensure_node_synced_up_to_slot<E: EthSpec>(
    network: LocalNetwork<E>,
    node_index: usize,
    upto_slot: Slot,
    slot_duration: Duration,
) -> Result<(), String> {
    slot_delay(upto_slot, slot_duration).await;
    let node = &network
        .remote_nodes()?
        .get(node_index)
        .expect("Should get node")
        .clone();

    let head = node
        .get_beacon_blocks::<E>(BlockId::Head)
        .await
        .ok()
        .flatten()
        .ok_or(format!("No head block exists on node {node_index}"))?
        .data;

    // Check the head block is synced with the rest of the network.
    if head.slot() >= upto_slot {
        Ok(())
    } else {
        Err(format!(
            "Head not synced for node {node_index}. Found {}; Should be {upto_slot}",
            head.slot()
        ))
    }
}

/// Verifies that there's been blobs produced at every slot with a block from `blob_start_slot` up
/// to and including `upto_slot`.
pub async fn verify_full_blob_production_up_to<E: EthSpec>(
    network: LocalNetwork<E>,
    blob_start_slot: Slot,
    upto_slot: Slot,
    slot_duration: Duration,
) -> Result<(), String> {
    slot_delay(upto_slot, slot_duration).await;
    let remote_nodes = network.remote_nodes()?;
    let remote_node = remote_nodes.first().unwrap();

    for slot in blob_start_slot.as_u64()..=upto_slot.as_u64() {
        // Ensure block exists.
        let block = remote_node
            .get_beacon_blocks::<E>(BlockId::Slot(Slot::new(slot)))
            .await
            .ok()
            .flatten();

        // Only check blobs if the block exists. If you also want to ensure full block production, use
        // the `verify_full_block_production_up_to` function.
        if block.is_some() {
            remote_node
                .get_blobs::<E>(BlockId::Slot(Slot::new(slot)), None)
                .await
                .map_err(|e| format!("Failed to get blobs at slot {slot:?}: {e:?}"))?
                .ok_or_else(|| format!("No blobs available at slot {slot:?}"))?;
        }
    }

    Ok(())
}

// Causes the beacon node at `node_index` to disconnect from the execution layer.
pub async fn disconnect_from_execution_layer<E: EthSpec>(
    network: LocalNetwork<E>,
    node_index: usize,
) -> Result<(), String> {
    eprintln!("Disabling Execution Node {node_index}");

    // Force the execution node to return the `syncing` status.
    network.execution_nodes.read()[node_index]
        .server
        .all_payloads_syncing(false);
    Ok(())
}

// Causes the beacon node at `node_index` to reconnect from the execution layer.
pub async fn reconnect_to_execution_layer<E: EthSpec>(
    network: LocalNetwork<E>,
    node_index: usize,
) -> Result<(), String> {
    network.execution_nodes.read()[node_index]
        .server
        .all_payloads_valid();

    eprintln!("Enabling Execution Node {node_index}");
    Ok(())
}

/// Ensure all validators have attested correctly.
pub async fn check_attestation_correctness<E: EthSpec>(
    network: LocalNetwork<E>,
    start_epoch: u64,
    upto_epoch: u64,
    slot_duration: Duration,
    // Select which node to query. Will use this node to determine the global network performance.
    node_index: usize,
    acceptable_attestation_performance: f64,
) -> Result<(), String> {
    epoch_delay(Epoch::new(upto_epoch), slot_duration, E::slots_per_epoch()).await;

    let remote_node = &network.remote_nodes()?[node_index];

    let results = remote_node
        .get_lighthouse_analysis_attestation_performance(
            Epoch::new(start_epoch),
            Epoch::new(upto_epoch - 2),
            "global".to_string(),
        )
        .await
        .map_err(|e| format!("Unable to get attestation performance: {e}"))?;

    let mut active_successes: f64 = 0.0;
    let mut head_successes: f64 = 0.0;
    let mut target_successes: f64 = 0.0;
    let mut source_successes: f64 = 0.0;

    let mut total: f64 = 0.0;

    for result in results {
        for epochs in result.epochs.values() {
            total += 1.0;

            if epochs.active {
                active_successes += 1.0;
            }
            if epochs.head {
                head_successes += 1.0;
            }
            if epochs.target {
                target_successes += 1.0;
            }
            if epochs.source {
                source_successes += 1.0;
            }
        }
    }
    let active_percent = active_successes / total * 100.0;
    let head_percent = head_successes / total * 100.0;
    let target_percent = target_successes / total * 100.0;
    let source_percent = source_successes / total * 100.0;

    eprintln!("Total Attestations: {}", total);
    eprintln!("Active: {}: {}%", active_successes, active_percent);
    eprintln!("Head: {}: {}%", head_successes, head_percent);
    eprintln!("Target: {}: {}%", target_successes, target_percent);
    eprintln!("Source: {}: {}%", source_successes, source_percent);

    if active_percent < acceptable_attestation_performance {
        return Err("Active percent was below required level".to_string());
    }
    if head_percent < acceptable_attestation_performance {
        return Err("Head percent was below required level".to_string());
    }
    if target_percent < acceptable_attestation_performance {
        return Err("Target percent was below required level".to_string());
    }
    if source_percent < acceptable_attestation_performance {
        return Err("Source percent was below required level".to_string());
    }

    Ok(())
}
