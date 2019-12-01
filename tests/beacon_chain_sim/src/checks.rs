use crate::local_network::LocalNetwork;
use futures::{stream, Future, IntoFuture, Stream};
use std::time::{Duration, Instant};
use tokio::timer::Delay;
use types::{Epoch, EthSpec, Slot, Unsigned};

/// Checks that all of the validators have on-boarded by the start of the second eth1 voting
/// period.
pub fn verify_initial_validator_count<E: EthSpec>(
    network: LocalNetwork<E>,
    slot_duration: Duration,
    initial_validator_count: usize,
) -> impl Future<Item = (), Error = String> {
    slot_delay(Slot::new(1), slot_duration)
        .and_then(move |()| verify_validator_count(network, initial_validator_count))
}

/// Checks that all of the validators have on-boarded by the start of the second eth1 voting
/// period.
pub fn verify_validator_onboarding<E: EthSpec>(
    network: LocalNetwork<E>,
    slot_duration: Duration,
    expected_validator_count: usize,
) -> impl Future<Item = (), Error = String> {
    slot_delay(
        Slot::new(E::SlotsPerEth1VotingPeriod::to_u64()),
        slot_duration,
    )
    .and_then(move |()| verify_validator_count(network, expected_validator_count))
}

/// Checks that the chain has made the first possible finalization.
///
/// Intended to be run as soon as chain starts.
pub fn verify_first_finalization<E: EthSpec>(
    network: LocalNetwork<E>,
    slot_duration: Duration,
) -> impl Future<Item = (), Error = String> {
    epoch_delay(Epoch::new(4), slot_duration, E::slots_per_epoch())
        .and_then(|()| verify_all_finalized_at(network, Epoch::new(2)))
}

/// Delays for `epochs`, plus half a slot extra.
fn epoch_delay(
    epochs: Epoch,
    slot_duration: Duration,
    slots_per_epoch: u64,
) -> impl Future<Item = (), Error = String> {
    let duration = slot_duration * (epochs.as_u64() * slots_per_epoch) as u32 + slot_duration / 2;

    Delay::new(Instant::now() + duration).map_err(|e| format!("Epoch delay failed: {:?}", e))
}

/// Delays for `slots`, plus half a slot extra.
fn slot_delay(slots: Slot, slot_duration: Duration) -> impl Future<Item = (), Error = String> {
    let duration = slot_duration * slots.as_u64() as u32 + slot_duration / 2;

    Delay::new(Instant::now() + duration).map_err(|e| format!("Epoch delay failed: {:?}", e))
}

/// Verifies that all beacon nodes in the given network have a head state that has a finalized
/// epoch of `epoch`.
fn verify_all_finalized_at<E: EthSpec>(
    network: LocalNetwork<E>,
    epoch: Epoch,
) -> impl Future<Item = (), Error = String> {
    network
        .remote_nodes()
        .into_future()
        .and_then(|remote_nodes| {
            stream::unfold(remote_nodes.into_iter(), |mut iter| {
                iter.next().map(|remote_node| {
                    remote_node
                        .http
                        .beacon()
                        .get_head()
                        .map(|head| head.finalized_slot.epoch(E::slots_per_epoch()))
                        .map(|epoch| (epoch, iter))
                        .map_err(|e| format!("Get head via http failed: {:?}", e))
                })
            })
            .collect()
        })
        .and_then(move |epochs| {
            if epochs.iter().any(|node_epoch| *node_epoch != epoch) {
                Err(format!(
                    "Nodes are not finalized at epoch {}. Finalized epochs: {:?}",
                    epoch, epochs
                ))
            } else {
                Ok(())
            }
        })
}

/// Verifies that all beacon nodes in the given `network` have a head state that contains
/// `expected_count` validators.
fn verify_validator_count<E: EthSpec>(
    network: LocalNetwork<E>,
    expected_count: usize,
) -> impl Future<Item = (), Error = String> {
    network
        .remote_nodes()
        .into_future()
        .and_then(|remote_nodes| {
            stream::unfold(remote_nodes.into_iter(), |mut iter| {
                iter.next().map(|remote_node| {
                    let beacon = remote_node.http.beacon();
                    beacon
                        .get_head()
                        .map_err(|e| format!("Get head via http failed: {:?}", e))
                        .and_then(move |head| {
                            beacon
                                .get_state_by_root(head.state_root)
                                .map(|(state, _root)| state)
                                .map_err(|e| format!("Get state root via http failed: {:?}", e))
                        })
                        .map(|state| (state.validators.len(), iter))
                })
            })
            .collect()
        })
        .and_then(move |validator_counts| {
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
        })
}
