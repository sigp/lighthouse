use crate::local_network::LocalNetwork;
use node_test_rig::eth2::types::{BlockId, StateId};
use std::time::Duration;
use types::{Epoch, EthSpec, Slot, Unsigned};

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
    altair_fork_version: [u8; 4],
) -> Result<(), String> {
    epoch_delay(fork_epoch, slot_duration, E::slots_per_epoch()).await;
    for remote_node in network.remote_nodes()? {
        let fork_version = remote_node
            .get_beacon_states_fork(StateId::Head)
            .await
            .map(|resp| resp.unwrap().data.current_version)
            .map_err(|e| format!("Failed to get fork from beacon node: {:?}", e))?;
        if fork_version != altair_fork_version {
            return Err(format!(
                "Fork version after FORK_EPOCH is incorrect, got: {:?}, expected: {:?}",
                fork_version, altair_fork_version,
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
            .ok_or(format!("Altair block {} should have sync aggregate", slot))?;

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
