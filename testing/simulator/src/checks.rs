use crate::local_network::LocalNetwork;
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
    tokio::time::delay_for(duration).await
}

/// Delays for `slots`, plus half a slot extra.
async fn slot_delay(slots: Slot, slot_duration: Duration) {
    let duration = slot_duration * slots.as_u64() as u32 + slot_duration / 2;
    tokio::time::delay_for(duration).await;
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
                    .http
                    .beacon()
                    .get_head()
                    .await
                    .map(|head| head.finalized_slot.epoch(E::slots_per_epoch()))
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
            let beacon = remote_node.http.beacon();

            let head = beacon
                .get_head()
                .await
                .map_err(|e| format!("Get head via http failed: {:?}", e))?;

            let vc = beacon
                .get_state_by_root(head.state_root)
                .await
                .map(|(state, _root)| state)
                .map_err(|e| format!("Get state root via http failed: {:?}", e))?
                .validators
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
    let chain_dump = beacon_chain.chain_dump().unwrap();
    if chain_dump.len() != slot.as_usize() + 1 {
        return Err(format!(
            "There wasn't a block produced at every slot, got: {}, expected: {}",
            chain_dump.len(),
            slot.as_usize() + 1
        ));
    }
    Ok(())
}
