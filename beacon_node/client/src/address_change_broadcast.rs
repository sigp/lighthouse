use crate::*;
use lighthouse_network::PubsubMessage;
use network::NetworkMessage;
use slog::{debug, info, warn, Logger};
use slot_clock::SlotClock;
use std::cmp;
use std::collections::HashSet;
use std::mem;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;
use types::EthSpec;

/// The size of each chunk of addresses changes to be broadcast at the Capella
/// fork.
const BROADCAST_CHUNK_SIZE: usize = 128;
/// The delay between broadcasting each chunk.
const BROADCAST_CHUNK_DELAY: Duration = Duration::from_millis(500);

/// If the Capella fork has already been reached, `broadcast_address_changes` is
/// called immediately.
///
/// If the Capella fork has not been reached, waits until the start of the fork
/// epoch and then calls `broadcast_address_changes`.
pub async fn broadcast_address_changes_at_capella<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    network_send: UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: &Logger,
) {
    let spec = &chain.spec;
    let slot_clock = &chain.slot_clock;

    let capella_fork_slot = if let Some(epoch) = spec.capella_fork_epoch {
        epoch.start_slot(T::EthSpec::slots_per_epoch())
    } else {
        // Exit now if Capella is not defined.
        return;
    };

    // Wait until the Capella fork epoch.
    while chain.slot().map_or(true, |slot| slot < capella_fork_slot) {
        match slot_clock.duration_to_slot(capella_fork_slot) {
            Some(duration) => {
                // Sleep until the Capella fork.
                sleep(duration).await;
                break;
            }
            None => {
                // We were unable to read the slot clock wait another slot
                // and then try again.
                sleep(slot_clock.slot_duration()).await;
            }
        }
    }

    // The following function will be called in two scenarios:
    //
    // 1. The node has been running for some time and the Capella fork has just
    //  been reached.
    // 2. The node has just started and it is *after* the Capella fork.
    broadcast_address_changes(chain, network_send, log).await
}

/// Broadcasts any address changes that are flagged for broadcasting at the
/// Capella fork epoch.
///
/// Address changes are published in chunks, with a delay between each chunk.
/// This helps reduce the load on the P2P network and also helps prevent us from
/// clogging our `network_send` channel and being late to publish
/// blocks, attestations, etc.
pub async fn broadcast_address_changes<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    network_send: UnboundedSender<NetworkMessage<T::EthSpec>>,
    log: &Logger,
) {
    let head = chain.head_snapshot();
    let mut changes = chain
        .op_pool
        .get_bls_to_execution_changes_received_pre_capella(&head.beacon_state, &chain.spec);

    while !changes.is_empty() {
        // This `split_off` approach is to allow us to have owned chunks of the
        // `changes` vec. The `std::slice::Chunks` method uses references and
        // the `itertools` iterator that achives this isn't `Send` so it doesn't
        // work well with the `sleep` at the end of the loop.
        let tail = changes.split_off(cmp::min(BROADCAST_CHUNK_SIZE, changes.len()));
        let chunk = mem::replace(&mut changes, tail);

        let mut published_indices = HashSet::with_capacity(BROADCAST_CHUNK_SIZE);
        let mut num_ok = 0;
        let mut num_err = 0;

        // Publish each individual address change.
        for address_change in chunk {
            let validator_index = address_change.message.validator_index;

            let pubsub_message = PubsubMessage::BlsToExecutionChange(Box::new(address_change));
            let message = NetworkMessage::Publish {
                messages: vec![pubsub_message],
            };
            // It seems highly unlikely that this unbounded send will fail, but
            // we handle the result nontheless.
            if let Err(e) = network_send.send(message) {
                debug!(
                    log,
                    "Failed to publish change message";
                    "error" => ?e,
                    "validator_index" => validator_index
                );
                num_err += 1;
            } else {
                debug!(
                    log,
                    "Published address change message";
                    "validator_index" => validator_index
                );
                num_ok += 1;
                published_indices.insert(validator_index);
            }
        }

        // Remove any published indices from the list of indices that need to be
        // published.
        chain
            .op_pool
            .register_indices_broadcasted_at_capella(&published_indices);

        info!(
            log,
            "Published address change messages";
            "num_published" => num_ok,
        );

        if num_err > 0 {
            warn!(
                log,
                "Failed to publish address changes";
                "info" => "failed messages will be retried",
                "num_unable_to_publish" => num_err,
            );
        }

        sleep(BROADCAST_CHUNK_DELAY).await;
    }

    debug!(
        log,
        "Address change routine complete";
    );
}

#[cfg(not(debug_assertions))] // Tests run too slow in debug.
#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
    use operation_pool::ReceivedPreCapella;
    use state_processing::{SigVerifiedOp, VerifyOperation};
    use std::collections::HashSet;
    use tokio::sync::mpsc;
    use types::*;

    type E = MainnetEthSpec;

    pub const VALIDATOR_COUNT: usize = BROADCAST_CHUNK_SIZE * 3;
    pub const EXECUTION_ADDRESS: Address = Address::repeat_byte(42);

    struct Tester {
        harness: BeaconChainHarness<EphemeralHarnessType<E>>,
        /// Changes which should be broadcast at the Capella fork.
        received_pre_capella_changes: Vec<SigVerifiedOp<SignedBlsToExecutionChange, E>>,
        /// Changes which should *not* be broadcast at the Capella fork.
        not_received_pre_capella_changes: Vec<SigVerifiedOp<SignedBlsToExecutionChange, E>>,
    }

    impl Tester {
        fn new() -> Self {
            let altair_fork_epoch = Epoch::new(0);
            let bellatrix_fork_epoch = Epoch::new(0);
            let capella_fork_epoch = Epoch::new(2);

            let mut spec = E::default_spec();
            spec.altair_fork_epoch = Some(altair_fork_epoch);
            spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
            spec.capella_fork_epoch = Some(capella_fork_epoch);

            let harness = BeaconChainHarness::builder(E::default())
                .spec(spec)
                .logger(logging::test_logger())
                .deterministic_keypairs(VALIDATOR_COUNT)
                .deterministic_withdrawal_keypairs(VALIDATOR_COUNT)
                .fresh_ephemeral_store()
                .mock_execution_layer()
                .build();

            Self {
                harness,
                received_pre_capella_changes: <_>::default(),
                not_received_pre_capella_changes: <_>::default(),
            }
        }

        fn produce_verified_address_change(
            &self,
            validator_index: u64,
        ) -> SigVerifiedOp<SignedBlsToExecutionChange, E> {
            let change = self
                .harness
                .make_bls_to_execution_change(validator_index, EXECUTION_ADDRESS);
            let head = self.harness.chain.head_snapshot();

            change
                .validate(&head.beacon_state, &self.harness.spec)
                .unwrap()
        }

        fn produce_received_pre_capella_changes(mut self, indices: Vec<u64>) -> Self {
            for validator_index in indices {
                self.received_pre_capella_changes
                    .push(self.produce_verified_address_change(validator_index));
            }
            self
        }

        fn produce_not_received_pre_capella_changes(mut self, indices: Vec<u64>) -> Self {
            for validator_index in indices {
                self.not_received_pre_capella_changes
                    .push(self.produce_verified_address_change(validator_index));
            }
            self
        }

        async fn run(self) {
            let harness = self.harness;
            let chain = harness.chain.clone();

            let mut broadcast_indices = HashSet::new();
            for change in self.received_pre_capella_changes {
                broadcast_indices.insert(change.as_inner().message.validator_index);
                chain
                    .op_pool
                    .insert_bls_to_execution_change(change, ReceivedPreCapella::Yes);
            }

            let mut non_broadcast_indices = HashSet::new();
            for change in self.not_received_pre_capella_changes {
                non_broadcast_indices.insert(change.as_inner().message.validator_index);
                chain
                    .op_pool
                    .insert_bls_to_execution_change(change, ReceivedPreCapella::No);
            }

            harness.set_current_slot(
                chain
                    .spec
                    .capella_fork_epoch
                    .unwrap()
                    .start_slot(E::slots_per_epoch()),
            );

            let (sender, mut receiver) = mpsc::unbounded_channel();

            broadcast_address_changes_at_capella(&chain, sender, &logging::test_logger()).await;

            let mut broadcasted_changes = vec![];
            while let Some(NetworkMessage::Publish { mut messages }) = receiver.recv().await {
                match messages.pop().unwrap() {
                    PubsubMessage::BlsToExecutionChange(change) => broadcasted_changes.push(change),
                    _ => panic!("unexpected message"),
                }
            }

            assert_eq!(
                broadcasted_changes.len(),
                broadcast_indices.len(),
                "all expected changes should have been broadcast"
            );

            for broadcasted in &broadcasted_changes {
                assert!(
                    !non_broadcast_indices.contains(&broadcasted.message.validator_index),
                    "messages not flagged for broadcast should not have been broadcast"
                );
            }

            let head = chain.head_snapshot();
            assert!(
                chain
                    .op_pool
                    .get_bls_to_execution_changes_received_pre_capella(
                        &head.beacon_state,
                        &chain.spec,
                    )
                    .is_empty(),
                "there shouldn't be any capella broadcast changes left in the op pool"
            );
        }
    }

    // Useful for generating even-numbered indices. Required since only even
    // numbered genesis validators have BLS credentials.
    fn even_indices(start: u64, count: usize) -> Vec<u64> {
        (start..).filter(|i| i % 2 == 0).take(count).collect()
    }

    #[tokio::test]
    async fn one_chunk() {
        Tester::new()
            .produce_received_pre_capella_changes(even_indices(0, 4))
            .produce_not_received_pre_capella_changes(even_indices(10, 4))
            .run()
            .await;
    }

    #[tokio::test]
    async fn multiple_chunks() {
        Tester::new()
            .produce_received_pre_capella_changes(even_indices(0, BROADCAST_CHUNK_SIZE * 3 / 2))
            .run()
            .await;
    }
}
