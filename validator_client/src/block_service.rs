use crate::beacon_node_fallback::{Error as FallbackError, Errors};
use crate::{
    beacon_node_fallback::{BeaconNodeFallback, RequireSynced},
    determine_graffiti,
    graffiti_file::GraffitiFile,
    OfflineOnFailure,
};
use crate::{
    http_metrics::metrics,
    validator_store::{Error as ValidatorStoreError, ValidatorStore},
};
use environment::RuntimeContext;
use eth2::BeaconNodeHttpClient;
use slog::{crit, debug, error, info, trace, warn};
use slot_clock::SlotClock;
use std::fmt::Debug;
use std::future::Future;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use types::{
    AbstractExecPayload, BlindedPayload, BlockType, EthSpec, FullPayload, Graffiti, PublicKeyBytes,
    Slot,
};

#[derive(Debug)]
pub enum BlockError {
    Recoverable(String),
    Irrecoverable(String),
}

impl From<Errors<BlockError>> for BlockError {
    fn from(e: Errors<BlockError>) -> Self {
        if e.0.iter().any(|(_, error)| {
            matches!(
                error,
                FallbackError::RequestFailed(BlockError::Irrecoverable(_))
            )
        }) {
            BlockError::Irrecoverable(e.to_string())
        } else {
            BlockError::Recoverable(e.to_string())
        }
    }
}

/// Builds a `BlockService`.
pub struct BlockServiceBuilder<T, E: EthSpec> {
    validator_store: Option<Arc<ValidatorStore<T, E>>>,
    slot_clock: Option<Arc<T>>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T, E>>>,
    proposer_nodes: Option<Arc<BeaconNodeFallback<T, E>>>,
    context: Option<RuntimeContext<E>>,
    graffiti: Option<Graffiti>,
    graffiti_file: Option<GraffitiFile>,
    block_delay: Option<Duration>,
}

impl<T: SlotClock + 'static, E: EthSpec> BlockServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            validator_store: None,
            slot_clock: None,
            beacon_nodes: None,
            proposer_nodes: None,
            context: None,
            graffiti: None,
            graffiti_file: None,
            block_delay: None,
        }
    }

    pub fn validator_store(mut self, store: Arc<ValidatorStore<T, E>>) -> Self {
        self.validator_store = Some(store);
        self
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(Arc::new(slot_clock));
        self
    }

    pub fn beacon_nodes(mut self, beacon_nodes: Arc<BeaconNodeFallback<T, E>>) -> Self {
        self.beacon_nodes = Some(beacon_nodes);
        self
    }

    pub fn proposer_nodes(mut self, proposer_nodes: Arc<BeaconNodeFallback<T, E>>) -> Self {
        self.proposer_nodes = Some(proposer_nodes);
        self
    }

    pub fn runtime_context(mut self, context: RuntimeContext<E>) -> Self {
        self.context = Some(context);
        self
    }

    pub fn graffiti(mut self, graffiti: Option<Graffiti>) -> Self {
        self.graffiti = graffiti;
        self
    }

    pub fn graffiti_file(mut self, graffiti_file: Option<GraffitiFile>) -> Self {
        self.graffiti_file = graffiti_file;
        self
    }

    pub fn block_delay(mut self, block_delay: Option<Duration>) -> Self {
        self.block_delay = block_delay;
        self
    }

    pub fn build(self) -> Result<BlockService<T, E>, String> {
        Ok(BlockService {
            inner: Arc::new(Inner {
                validator_store: self
                    .validator_store
                    .ok_or("Cannot build BlockService without validator_store")?,
                slot_clock: self
                    .slot_clock
                    .ok_or("Cannot build BlockService without slot_clock")?,
                beacon_nodes: self
                    .beacon_nodes
                    .ok_or("Cannot build BlockService without beacon_node")?,
                context: self
                    .context
                    .ok_or("Cannot build BlockService without runtime_context")?,
                proposer_nodes: self.proposer_nodes,
                graffiti: self.graffiti,
                graffiti_file: self.graffiti_file,
                block_delay: self.block_delay,
            }),
        })
    }
}

// Combines a set of non-block-proposing `beacon_nodes` and only-block-proposing
// `proposer_nodes`.
pub struct ProposerFallback<T, E: EthSpec> {
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    proposer_nodes: Option<Arc<BeaconNodeFallback<T, E>>>,
}

impl<T: SlotClock, E: EthSpec> ProposerFallback<T, E> {
    // Try `func` on `self.proposer_nodes` first. If that doesn't work, try `self.beacon_nodes`.
    pub async fn first_success_try_proposers_first<'a, F, O, Err, R>(
        &'a self,
        require_synced: RequireSynced,
        offline_on_failure: OfflineOnFailure,
        func: F,
    ) -> Result<O, Errors<Err>>
    where
        F: Fn(&'a BeaconNodeHttpClient) -> R + Clone,
        R: Future<Output = Result<O, Err>>,
        Err: Debug,
    {
        // If there are proposer nodes, try calling `func` on them and return early if they are successful.
        if let Some(proposer_nodes) = &self.proposer_nodes {
            if let Ok(result) = proposer_nodes
                .first_success(require_synced, offline_on_failure, func.clone())
                .await
            {
                return Ok(result);
            }
        }

        // If the proposer nodes failed, try on the non-proposer nodes.
        self.beacon_nodes
            .first_success(require_synced, offline_on_failure, func)
            .await
    }

    // Try `func` on `self.beacon_nodes` first. If that doesn't work, try `self.proposer_nodes`.
    pub async fn first_success_try_proposers_last<'a, F, O, Err, R>(
        &'a self,
        require_synced: RequireSynced,
        offline_on_failure: OfflineOnFailure,
        func: F,
    ) -> Result<O, Errors<Err>>
    where
        F: Fn(&'a BeaconNodeHttpClient) -> R + Clone,
        R: Future<Output = Result<O, Err>>,
        Err: Debug,
    {
        // Try running `func` on the non-proposer beacon nodes.
        let beacon_nodes_result = self
            .beacon_nodes
            .first_success(require_synced, offline_on_failure, func.clone())
            .await;

        match (beacon_nodes_result, &self.proposer_nodes) {
            // The non-proposer node call succeed, return the result.
            (Ok(success), _) => Ok(success),
            // The non-proposer node call failed, but we don't have any proposer nodes. Return an error.
            (Err(e), None) => Err(e),
            // The non-proposer node call failed, try the same call on the proposer nodes.
            (Err(_), Some(proposer_nodes)) => {
                proposer_nodes
                    .first_success(require_synced, offline_on_failure, func)
                    .await
            }
        }
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    validator_store: Arc<ValidatorStore<T, E>>,
    slot_clock: Arc<T>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    proposer_nodes: Option<Arc<BeaconNodeFallback<T, E>>>,
    context: RuntimeContext<E>,
    graffiti: Option<Graffiti>,
    graffiti_file: Option<GraffitiFile>,
    block_delay: Option<Duration>,
}

/// Attempts to produce attestations for any block producer(s) at the start of the epoch.
pub struct BlockService<T, E: EthSpec> {
    inner: Arc<Inner<T, E>>,
}

impl<T, E: EthSpec> Clone for BlockService<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T, E: EthSpec> Deref for BlockService<T, E> {
    type Target = Inner<T, E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

/// Notification from the duties service that we should try to produce a block.
pub struct BlockServiceNotification {
    pub slot: Slot,
    pub block_proposers: Vec<PublicKeyBytes>,
}

impl<T: SlotClock + 'static, E: EthSpec> BlockService<T, E> {
    pub fn start_update_service(
        self,
        mut notification_rx: mpsc::Receiver<BlockServiceNotification>,
    ) -> Result<(), String> {
        let log = self.context.log().clone();

        info!(log, "Block production service started");

        let executor = self.inner.context.executor.clone();

        executor.spawn(
            async move {
                while let Some(notif) = notification_rx.recv().await {
                    let service = self.clone();

                    if let Some(delay) = service.block_delay {
                        debug!(
                            service.context.log(),
                            "Delaying block production by {}ms",
                            delay.as_millis()
                        );
                        sleep(delay).await;
                    }

                    service.do_update(notif).await.ok();
                }
                debug!(log, "Block service shutting down");
            },
            "block_service",
        );

        Ok(())
    }

    /// Attempt to produce a block for any block producers in the `ValidatorStore`.
    async fn do_update(&self, notification: BlockServiceNotification) -> Result<(), ()> {
        let log = self.context.log();
        let _timer =
            metrics::start_timer_vec(&metrics::BLOCK_SERVICE_TIMES, &[metrics::FULL_UPDATE]);

        let slot = self.slot_clock.now().ok_or_else(move || {
            crit!(log, "Duties manager failed to read slot clock");
        })?;

        if notification.slot != slot {
            warn!(
                log,
                "Skipping block production for expired slot";
                "current_slot" => slot.as_u64(),
                "notification_slot" => notification.slot.as_u64(),
                "info" => "Your machine could be overloaded"
            );
            return Ok(());
        }

        if slot == self.context.eth2_config.spec.genesis_slot {
            debug!(
                log,
                "Not producing block at genesis slot";
                "proposers" => format!("{:?}", notification.block_proposers),
            );
            return Ok(());
        }

        trace!(
            log,
            "Block service update started";
            "slot" => slot.as_u64()
        );

        let proposers = notification.block_proposers;

        if proposers.is_empty() {
            trace!(
                log,
                "No local block proposers for this slot";
                "slot" => slot.as_u64()
            )
        } else if proposers.len() > 1 {
            error!(
                log,
                "Multiple block proposers for this slot";
                "action" => "producing blocks for all proposers",
                "num_proposers" => proposers.len(),
                "slot" => slot.as_u64(),
            )
        }

        for validator_pubkey in proposers {
            let builder_proposals = self
                .validator_store
                .get_builder_proposals(&validator_pubkey);
            let service = self.clone();
            let log = log.clone();
            self.inner.context.executor.spawn(
                async move {
                    if builder_proposals {
                        let result = service
                            .clone()
                            .publish_block::<BlindedPayload<E>>(slot, validator_pubkey)
                            .await;
                        match result {
                            Err(BlockError::Recoverable(e)) => {
                                error!(
                                    log,
                                    "Error whilst producing block";
                                    "error" => ?e,
                                    "block_slot" => ?slot,
                                    "info" => "blinded proposal failed, attempting full block"
                                );
                                if let Err(e) = service
                                    .publish_block::<FullPayload<E>>(slot, validator_pubkey)
                                    .await
                                {
                                    // Log a `crit` since a full block
                                    // (non-builder) proposal failed.
                                    crit!(
                                        log,
                                        "Error whilst producing block";
                                        "error" => ?e,
                                        "block_slot" => ?slot,
                                        "info" => "full block attempted after a blinded failure",
                                    );
                                }
                            }
                            Err(BlockError::Irrecoverable(e)) => {
                                // Only log an `error` since it's common for
                                // builders to timeout on their response, only
                                // to publish the block successfully themselves.
                                error!(
                                    log,
                                    "Error whilst producing block";
                                    "error" => ?e,
                                    "block_slot" => ?slot,
                                    "info" => "this error may or may not result in a missed block",
                                )
                            }
                            Ok(_) => {}
                        };
                    } else if let Err(e) = service
                        .publish_block::<FullPayload<E>>(slot, validator_pubkey)
                        .await
                    {
                        // Log a `crit` since a full block (non-builder)
                        // proposal failed.
                        crit!(
                            log,
                            "Error whilst producing block";
                            "message" => ?e,
                            "block_slot" => ?slot,
                            "info" => "proposal did not use a builder",
                        );
                    }
                },
                "block service",
            );
        }

        Ok(())
    }

    /// Produce a block at the given slot for validator_pubkey
    async fn publish_block<Payload: AbstractExecPayload<E>>(
        self,
        slot: Slot,
        validator_pubkey: PublicKeyBytes,
    ) -> Result<(), BlockError> {
        let log = self.context.log();
        let _timer =
            metrics::start_timer_vec(&metrics::BLOCK_SERVICE_TIMES, &[metrics::BEACON_BLOCK]);

        let current_slot = self.slot_clock.now().ok_or_else(|| {
            BlockError::Recoverable("Unable to determine current slot from clock".to_string())
        })?;

        let randao_reveal = match self
            .validator_store
            .randao_reveal(validator_pubkey, slot.epoch(E::slots_per_epoch()))
            .await
        {
            Ok(signature) => signature.into(),
            Err(ValidatorStoreError::UnknownPubkey(pubkey)) => {
                // A pubkey can be missing when a validator was recently removed
                // via the API.
                warn!(
                    log,
                    "Missing pubkey for block randao";
                    "info" => "a validator may have recently been removed from this VC",
                    "pubkey" => ?pubkey,
                    "slot" => ?slot
                );
                return Ok(());
            }
            Err(e) => {
                return Err(BlockError::Recoverable(format!(
                    "Unable to produce randao reveal signature: {:?}",
                    e
                )))
            }
        };

        let graffiti = determine_graffiti(
            &validator_pubkey,
            log,
            self.graffiti_file.clone(),
            self.validator_store.graffiti(&validator_pubkey),
            self.graffiti,
        );

        let randao_reveal_ref = &randao_reveal;
        let self_ref = &self;
        let proposer_index = self.validator_store.validator_index(&validator_pubkey);
        let validator_pubkey_ref = &validator_pubkey;
        let proposer_fallback = ProposerFallback {
            beacon_nodes: self.beacon_nodes.clone(),
            proposer_nodes: self.proposer_nodes.clone(),
        };

        info!(
            log,
            "Requesting unsigned block";
            "slot" => slot.as_u64(),
        );

        // Request block from first responsive beacon node.
        //
        // Try the proposer nodes last, since it's likely that they don't have a
        // great view of attestations on the network.
        let block = proposer_fallback
            .first_success_try_proposers_last(
                RequireSynced::No,
                OfflineOnFailure::Yes,
                |beacon_node| async move {
                    let block = match Payload::block_type() {
                        BlockType::Full => {
                            let _get_timer = metrics::start_timer_vec(
                                &metrics::BLOCK_SERVICE_TIMES,
                                &[metrics::BEACON_BLOCK_HTTP_GET],
                            );
                            beacon_node
                                .get_validator_blocks::<E, Payload>(
                                    slot,
                                    randao_reveal_ref,
                                    graffiti.as_ref(),
                                )
                                .await
                                .map_err(|e| {
                                    BlockError::Recoverable(format!(
                                        "Error from beacon node when producing block: {:?}",
                                        e
                                    ))
                                })?
                                .data
                        }
                        BlockType::Blinded => {
                            let _get_timer = metrics::start_timer_vec(
                                &metrics::BLOCK_SERVICE_TIMES,
                                &[metrics::BLINDED_BEACON_BLOCK_HTTP_GET],
                            );
                            beacon_node
                                .get_validator_blinded_blocks::<E, Payload>(
                                    slot,
                                    randao_reveal_ref,
                                    graffiti.as_ref(),
                                )
                                .await
                                .map_err(|e| {
                                    BlockError::Recoverable(format!(
                                        "Error from beacon node when producing block: {:?}",
                                        e
                                    ))
                                })?
                                .data
                        }
                    };

                    info!(
                        log,
                        "Received unsigned block";
                        "slot" => slot.as_u64(),
                    );
                    if proposer_index != Some(block.proposer_index()) {
                        return Err(BlockError::Recoverable(
                            "Proposer index does not match block proposer. Beacon chain re-orged"
                                .to_string(),
                        ));
                    }

                    Ok::<_, BlockError>(block)
                },
            )
            .await?;

        let signing_timer = metrics::start_timer(&metrics::BLOCK_SIGNING_TIMES);
        let signed_block = match self_ref
            .validator_store
            .sign_block::<Payload>(*validator_pubkey_ref, block, current_slot)
            .await
        {
            Ok(block) => block,
            Err(ValidatorStoreError::UnknownPubkey(pubkey)) => {
                // A pubkey can be missing when a validator was recently removed
                // via the API.
                warn!(
                    log,
                    "Missing pubkey for block";
                    "info" => "a validator may have recently been removed from this VC",
                    "pubkey" => ?pubkey,
                    "slot" => ?slot
                );
                return Ok(());
            }
            Err(e) => {
                return Err(BlockError::Recoverable(format!(
                    "Unable to sign block: {:?}",
                    e
                )))
            }
        };
        let signing_time_ms =
            Duration::from_secs_f64(signing_timer.map_or(0.0, |t| t.stop_and_record())).as_millis();

        info!(
            log,
            "Publishing signed block";
            "slot" => slot.as_u64(),
            "signing_time_ms" => signing_time_ms,
        );

        // Publish block with first available beacon node.
        //
        // Try the proposer nodes first, since we've likely gone to efforts to
        // protect them from DoS attacks and they're most likely to successfully
        // publish a block.
        proposer_fallback
            .first_success_try_proposers_first(
                RequireSynced::No,
                OfflineOnFailure::Yes,
                |beacon_node| async {
                    match Payload::block_type() {
                        BlockType::Full => {
                            let _post_timer = metrics::start_timer_vec(
                                &metrics::BLOCK_SERVICE_TIMES,
                                &[metrics::BEACON_BLOCK_HTTP_POST],
                            );
                            beacon_node
                                .post_beacon_blocks(&signed_block)
                                .await
                                .map_err(|e| {
                                    BlockError::Irrecoverable(format!(
                                        "Error from beacon node when publishing block: {:?}",
                                        e
                                    ))
                                })?
                        }
                        BlockType::Blinded => {
                            let _post_timer = metrics::start_timer_vec(
                                &metrics::BLOCK_SERVICE_TIMES,
                                &[metrics::BLINDED_BEACON_BLOCK_HTTP_POST],
                            );
                            beacon_node
                                .post_beacon_blinded_blocks(&signed_block)
                                .await
                                .map_err(|e| {
                                    BlockError::Irrecoverable(format!(
                                        "Error from beacon node when publishing block: {:?}",
                                        e
                                    ))
                                })?
                        }
                    }
                    Ok::<_, BlockError>(())
                },
            )
            .await?;

        info!(
            log,
            "Successfully published block";
            "block_type" => ?Payload::block_type(),
            "deposits" => signed_block.message().body().deposits().len(),
            "attestations" => signed_block.message().body().attestations().len(),
            "graffiti" => ?graffiti.map(|g| g.as_utf8_lossy()),
            "slot" => signed_block.slot().as_u64(),
        );

        Ok(())
    }
}
