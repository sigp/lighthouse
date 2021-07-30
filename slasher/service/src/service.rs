use beacon_chain::{
    observed_operations::ObservationOutcome, BeaconChain, BeaconChainError, BeaconChainTypes,
};
use directory::size_of_dir;
use eth2_libp2p::PubsubMessage;
use network::NetworkMessage;
use slasher::{
    metrics::{self, SLASHER_DATABASE_SIZE, SLASHER_RUN_TIME},
    Slasher,
};
use slog::{debug, error, info, trace, warn, Logger};
use slot_clock::SlotClock;
use state_processing::{
    per_block_processing::errors::{
        AttesterSlashingInvalid, BlockOperationError, ProposerSlashingInvalid,
    },
    VerifyOperation,
};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{interval_at, Duration, Instant};
use types::{AttesterSlashing, Epoch, EthSpec, ProposerSlashing};

pub struct SlasherService<T: BeaconChainTypes> {
    beacon_chain: Arc<BeaconChain<T>>,
    network_sender: UnboundedSender<NetworkMessage<T::EthSpec>>,
}

impl<T: BeaconChainTypes> SlasherService<T> {
    /// Create a new service but don't start any tasks yet.
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_sender: UnboundedSender<NetworkMessage<T::EthSpec>>,
    ) -> Self {
        Self {
            beacon_chain,
            network_sender,
        }
    }

    /// Start the slasher service tasks on the `executor`.
    pub fn run(&self, executor: &TaskExecutor) -> Result<(), String> {
        let slasher = self
            .beacon_chain
            .slasher
            .clone()
            .ok_or("No slasher is configured")?;
        let log = slasher.log().clone();

        info!(log, "Starting slasher"; "broadcast" => slasher.config().broadcast);

        // Buffer just a single message in the channel. If the receiver is still processing, we
        // don't need to burden them with more work (we can wait).
        let (notif_sender, notif_receiver) = sync_channel(1);
        let update_period = slasher.config().update_period;
        let beacon_chain = self.beacon_chain.clone();
        let network_sender = self.network_sender.clone();

        executor.spawn(
            Self::run_notifier(beacon_chain.clone(), update_period, notif_sender, log),
            "slasher_server_notifier",
        );

        executor.spawn_blocking(
            || Self::run_processor(beacon_chain, slasher, notif_receiver, network_sender),
            "slasher_server_processor",
        );

        Ok(())
    }

    /// Run the async notifier which periodically prompts the processor to run.
    async fn run_notifier(
        beacon_chain: Arc<BeaconChain<T>>,
        update_period: u64,
        notif_sender: SyncSender<Epoch>,
        log: Logger,
    ) {
        // NOTE: could align each run to some fixed point in each slot, see:
        // https://github.com/sigp/lighthouse/issues/1861
        let mut interval = interval_at(Instant::now(), Duration::from_secs(update_period));

        loop {
            interval.tick().await;
            if let Some(current_slot) = beacon_chain.slot_clock.now() {
                let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());
                if let Err(TrySendError::Disconnected(_)) = notif_sender.try_send(current_epoch) {
                    break;
                }
            } else {
                trace!(log, "Slasher has nothing to do: we are pre-genesis");
            }
        }
    }

    /// Run the blocking task that performs work.
    fn run_processor(
        beacon_chain: Arc<BeaconChain<T>>,
        slasher: Arc<Slasher<T::EthSpec>>,
        notif_receiver: Receiver<Epoch>,
        network_sender: UnboundedSender<NetworkMessage<T::EthSpec>>,
    ) {
        let log = slasher.log();
        while let Ok(current_epoch) = notif_receiver.recv() {
            let t = Instant::now();

            let batch_timer = metrics::start_timer(&SLASHER_RUN_TIME);
            let stats = match slasher.process_queued(current_epoch) {
                Ok(stats) => Some(stats),
                Err(e) => {
                    error!(
                        log,
                        "Error during scheduled slasher processing";
                        "epoch" => current_epoch,
                        "error" => format!("{:?}", e)
                    );
                    None
                }
            };
            drop(batch_timer);

            // Prune the database, even in the case where batch processing failed.
            // If the LMDB database is full then pruning could help to free it up.
            if let Err(e) = slasher.prune_database(current_epoch) {
                error!(
                    log,
                    "Error during slasher database pruning";
                    "epoch" => current_epoch,
                    "error" => format!("{:?}", e),
                );
                continue;
            };

            // Provide slashings to the beacon chain, and optionally publish them.
            Self::process_slashings(&beacon_chain, &slasher, &network_sender);

            let database_size = size_of_dir(&slasher.config().database_path);
            metrics::set_gauge(&SLASHER_DATABASE_SIZE, database_size as i64);

            if let Some(stats) = stats {
                debug!(
                    log,
                    "Completed slasher update";
                    "epoch" => current_epoch,
                    "time_taken" => format!("{}ms", t.elapsed().as_millis()),
                    "num_attestations" => stats.attestation_stats.num_processed,
                    "num_blocks" => stats.block_stats.num_processed,
                );
            }
        }
    }

    /// Push any slashings found to the beacon chain, optionally publishing them on the network.
    fn process_slashings(
        beacon_chain: &BeaconChain<T>,
        slasher: &Slasher<T::EthSpec>,
        network_sender: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    ) {
        Self::process_attester_slashings(beacon_chain, slasher, network_sender);
        Self::process_proposer_slashings(beacon_chain, slasher, network_sender);
    }

    fn process_attester_slashings(
        beacon_chain: &BeaconChain<T>,
        slasher: &Slasher<T::EthSpec>,
        network_sender: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    ) {
        let log = slasher.log();
        let attester_slashings = slasher.get_attester_slashings();

        for slashing in attester_slashings {
            // Verify slashing signature.
            let verified_slashing = match beacon_chain.with_head(|head| {
                Ok::<_, BeaconChainError>(
                    slashing
                        .clone()
                        .validate(&head.beacon_state, &beacon_chain.spec)?,
                )
            }) {
                Ok(verified) => verified,
                Err(BeaconChainError::AttesterSlashingValidationError(
                    BlockOperationError::Invalid(AttesterSlashingInvalid::NoSlashableIndices),
                )) => {
                    debug!(
                        log,
                        "Skipping attester slashing for slashed validators";
                        "slashing" => ?slashing,
                    );
                    continue;
                }
                Err(e) => {
                    warn!(
                        log,
                        "Attester slashing produced is invalid";
                        "error" => ?e,
                        "slashing" => ?slashing,
                    );
                    continue;
                }
            };

            // Add to local op pool.
            if let Err(e) = beacon_chain.import_attester_slashing(verified_slashing) {
                error!(
                    log,
                    "Beacon chain refused attester slashing";
                    "error" => ?e,
                    "slashing" => ?slashing,
                );
            }

            // Publish to the network if broadcast is enabled.
            if slasher.config().broadcast {
                if let Err(e) =
                    Self::publish_attester_slashing(beacon_chain, network_sender, slashing)
                {
                    debug!(
                        log,
                        "Unable to publish attester slashing";
                        "error" => e,
                    );
                }
            }
        }
    }

    fn process_proposer_slashings(
        beacon_chain: &BeaconChain<T>,
        slasher: &Slasher<T::EthSpec>,
        network_sender: &UnboundedSender<NetworkMessage<T::EthSpec>>,
    ) {
        let log = slasher.log();
        let proposer_slashings = slasher.get_proposer_slashings();

        for slashing in proposer_slashings {
            let verified_slashing = match beacon_chain.with_head(|head| {
                Ok(slashing
                    .clone()
                    .validate(&head.beacon_state, &beacon_chain.spec)?)
            }) {
                Ok(verified) => verified,
                Err(BeaconChainError::ProposerSlashingValidationError(
                    BlockOperationError::Invalid(ProposerSlashingInvalid::ProposerNotSlashable(
                        index,
                    )),
                )) => {
                    debug!(
                        log,
                        "Skipping proposer slashing for slashed validator";
                        "validator_index" => index,
                    );
                    continue;
                }
                Err(e) => {
                    error!(
                        log,
                        "Proposer slashing produced is invalid";
                        "error" => ?e,
                        "slashing" => ?slashing,
                    );
                    continue;
                }
            };
            beacon_chain.import_proposer_slashing(verified_slashing);

            if slasher.config().broadcast {
                if let Err(e) =
                    Self::publish_proposer_slashing(beacon_chain, network_sender, slashing)
                {
                    debug!(
                        log,
                        "Unable to publish proposer slashing";
                        "error" => e,
                    );
                }
            }
        }
    }

    fn publish_attester_slashing(
        beacon_chain: &BeaconChain<T>,
        network_sender: &UnboundedSender<NetworkMessage<T::EthSpec>>,
        slashing: AttesterSlashing<T::EthSpec>,
    ) -> Result<(), String> {
        let outcome = beacon_chain
            .verify_attester_slashing_for_gossip(slashing)
            .map_err(|e| format!("gossip verification error: {:?}", e))?;

        if let ObservationOutcome::New(slashing) = outcome {
            network_sender
                .send(NetworkMessage::Publish {
                    messages: vec![PubsubMessage::AttesterSlashing(Box::new(
                        slashing.into_inner(),
                    ))],
                })
                .map_err(|e| format!("network error: {:?}", e))?;
        }
        Ok(())
    }

    fn publish_proposer_slashing(
        beacon_chain: &BeaconChain<T>,
        network_sender: &UnboundedSender<NetworkMessage<T::EthSpec>>,
        slashing: ProposerSlashing,
    ) -> Result<(), String> {
        let outcome = beacon_chain
            .verify_proposer_slashing_for_gossip(slashing)
            .map_err(|e| format!("gossip verification error: {:?}", e))?;

        if let ObservationOutcome::New(slashing) = outcome {
            network_sender
                .send(NetworkMessage::Publish {
                    messages: vec![PubsubMessage::ProposerSlashing(Box::new(
                        slashing.into_inner(),
                    ))],
                })
                .map_err(|e| format!("network error: {:?}", e))?;
        }
        Ok(())
    }
}
