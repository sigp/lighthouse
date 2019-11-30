use crate::local_network::LocalNetwork;
use futures::{stream, Future, IntoFuture, Stream};
use std::time::{Duration, Instant};
use tokio::timer::Delay;
use types::{Epoch, EthSpec};

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
