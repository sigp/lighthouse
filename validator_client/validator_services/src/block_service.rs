use beacon_node_fallback::{ApiTopic, BeaconNodeFallback, Error as FallbackError, Errors};
use bls::SignatureBytes;
use eth2::{BeaconNodeHttpClient, StatusCode};
use graffiti_file::{GraffitiFile, determine_graffiti};
use logging::crit;
use slot_clock::SlotClock;
use std::fmt::Debug;
use std::future::Future;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};
use types::{BlockType, ChainSpec, EthSpec, Graffiti, PublicKeyBytes, Slot};
use validator_store::{Error as ValidatorStoreError, SignedBlock, UnsignedBlock, ValidatorStore};

#[derive(Debug)]
pub enum BlockError {
    /// A recoverable error that can be retried, as the validator has not signed anything.
    Recoverable(String),
    /// An irrecoverable error has occurred during block proposal and should not be retried, as a
    /// block may have already been signed.
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
#[derive(Default)]
pub struct BlockServiceBuilder<S, T> {
    validator_store: Option<Arc<S>>,
    slot_clock: Option<Arc<T>>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T>>>,
    proposer_nodes: Option<Arc<BeaconNodeFallback<T>>>,
    executor: Option<TaskExecutor>,
    chain_spec: Option<Arc<ChainSpec>>,
    graffiti: Option<Graffiti>,
    graffiti_file: Option<GraffitiFile>,
}

impl<S: ValidatorStore, T: SlotClock + 'static> BlockServiceBuilder<S, T> {
    pub fn new() -> Self {
        Self {
            validator_store: None,
            slot_clock: None,
            beacon_nodes: None,
            proposer_nodes: None,
            executor: None,
            chain_spec: None,
            graffiti: None,
            graffiti_file: None,
        }
    }

    pub fn validator_store(mut self, store: Arc<S>) -> Self {
        self.validator_store = Some(store);
        self
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(Arc::new(slot_clock));
        self
    }

    pub fn beacon_nodes(mut self, beacon_nodes: Arc<BeaconNodeFallback<T>>) -> Self {
        self.beacon_nodes = Some(beacon_nodes);
        self
    }

    pub fn proposer_nodes(mut self, proposer_nodes: Arc<BeaconNodeFallback<T>>) -> Self {
        self.proposer_nodes = Some(proposer_nodes);
        self
    }

    pub fn executor(mut self, executor: TaskExecutor) -> Self {
        self.executor = Some(executor);
        self
    }

    pub fn chain_spec(mut self, chain_spec: Arc<ChainSpec>) -> Self {
        self.chain_spec = Some(chain_spec);
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

    pub fn build(self) -> Result<BlockService<S, T>, String> {
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
                executor: self
                    .executor
                    .ok_or("Cannot build BlockService without executor")?,
                chain_spec: self
                    .chain_spec
                    .ok_or("Cannot build BlockService without chain_spec")?,
                proposer_nodes: self.proposer_nodes,
                graffiti: self.graffiti,
                graffiti_file: self.graffiti_file,
            }),
        })
    }
}

// Combines a set of non-block-proposing `beacon_nodes` and only-block-proposing
// `proposer_nodes`.
pub struct ProposerFallback<T> {
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    proposer_nodes: Option<Arc<BeaconNodeFallback<T>>>,
}

impl<T: SlotClock> ProposerFallback<T> {
    // Try `func` on `self.proposer_nodes` first. If that doesn't work, try `self.beacon_nodes`.
    pub async fn request_proposers_first<F, Err, R>(&self, func: F) -> Result<(), Errors<Err>>
    where
        F: Fn(BeaconNodeHttpClient) -> R + Clone,
        R: Future<Output = Result<(), Err>>,
        Err: Debug,
    {
        // If there are proposer nodes, try calling `func` on them and return early if they are successful.
        if let Some(proposer_nodes) = &self.proposer_nodes
            && proposer_nodes
                .request(ApiTopic::Blocks, func.clone())
                .await
                .is_ok()
        {
            return Ok(());
        }

        // If the proposer nodes failed, try on the non-proposer nodes.
        self.beacon_nodes.request(ApiTopic::Blocks, func).await
    }

    // Try `func` on `self.beacon_nodes` first. If that doesn't work, try `self.proposer_nodes`.
    pub async fn request_proposers_last<F, O, Err, R>(&self, func: F) -> Result<O, Errors<Err>>
    where
        F: Fn(BeaconNodeHttpClient) -> R + Clone,
        R: Future<Output = Result<O, Err>>,
        Err: Debug,
    {
        // Try running `func` on the non-proposer beacon nodes.
        let beacon_nodes_result = self.beacon_nodes.first_success(func.clone()).await;

        match (beacon_nodes_result, &self.proposer_nodes) {
            // The non-proposer node call succeed, return the result.
            (Ok(success), _) => Ok(success),
            // The non-proposer node call failed, but we don't have any proposer nodes. Return an error.
            (Err(e), None) => Err(e),
            // The non-proposer node call failed, try the same call on the proposer nodes.
            (Err(_), Some(proposer_nodes)) => proposer_nodes.first_success(func).await,
        }
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<S, T> {
    validator_store: Arc<S>,
    slot_clock: Arc<T>,
    pub beacon_nodes: Arc<BeaconNodeFallback<T>>,
    pub proposer_nodes: Option<Arc<BeaconNodeFallback<T>>>,
    executor: TaskExecutor,
    chain_spec: Arc<ChainSpec>,
    graffiti: Option<Graffiti>,
    graffiti_file: Option<GraffitiFile>,
}

/// Attempts to produce attestations for any block producer(s) at the start of the epoch.
pub struct BlockService<S, T> {
    inner: Arc<Inner<S, T>>,
}

impl<S, T> Clone for BlockService<S, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, T> Deref for BlockService<S, T> {
    type Target = Inner<S, T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

/// Notification from the duties service that we should try to produce a block.
pub struct BlockServiceNotification {
    pub slot: Slot,
    pub block_proposers: Vec<PublicKeyBytes>,
}

impl<S: ValidatorStore + 'static, T: SlotClock + 'static> BlockService<S, T> {
    pub fn start_update_service(
        self,
        mut notification_rx: mpsc::Receiver<BlockServiceNotification>,
    ) -> Result<(), String> {
        info!("Block production service started");

        let executor = self.inner.executor.clone();

        executor.spawn(
            async move {
                while let Some(notif) = notification_rx.recv().await {
                    self.do_update(notif).await.ok();
                }
                debug!("Block service shutting down");
            },
            "block_service",
        );

        Ok(())
    }

    /// Attempt to produce a block for any block producers in the `ValidatorStore`.
    async fn do_update(&self, notification: BlockServiceNotification) -> Result<(), ()> {
        let _timer = validator_metrics::start_timer_vec(
            &validator_metrics::BLOCK_SERVICE_TIMES,
            &[validator_metrics::FULL_UPDATE],
        );

        let slot = self.slot_clock.now().ok_or_else(move || {
            crit!("Duties manager failed to read slot clock");
        })?;

        if notification.slot != slot {
            warn!(
                current_slot = slot.as_u64(),
                notification_slot = notification.slot.as_u64(),
                info = "Your machine could be overloaded",
                "Skipping block production for expired slot"
            );
            return Ok(());
        }

        if slot == self.chain_spec.genesis_slot {
            debug!(
                proposers = format!("{:?}", notification.block_proposers),
                "Not producing block at genesis slot"
            );
            return Ok(());
        }

        trace!(slot = slot.as_u64(), "Block service update started");

        let proposers = notification.block_proposers;

        if proposers.is_empty() {
            trace!(
                slot = slot.as_u64(),
                "No local block proposers for this slot"
            )
        } else if proposers.len() > 1 {
            error!(
                action = "producing blocks for all proposers",
                num_proposers = proposers.len(),
                slot = slot.as_u64(),
                "Multiple block proposers for this slot"
            )
        }

        for validator_pubkey in proposers {
            let builder_boost_factor = self
                .validator_store
                .determine_builder_boost_factor(&validator_pubkey);
            let service = self.clone();
            self.inner.executor.spawn(
                async move {
                    let result = service
                        .publish_block(slot, validator_pubkey, builder_boost_factor)
                        .await;

                    match result {
                        Ok(_) => {}
                        Err(BlockError::Recoverable(e)) | Err(BlockError::Irrecoverable(e)) => {
                            error!(
                                error = ?e,
                                block_slot = ?slot,
                                info = "block v3 proposal failed, this error may or may not result in a missed block",
                                "Error whilst producing block"
                            );
                        }
                    }
                },
                "block service",
            )
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn sign_and_publish_block(
        &self,
        proposer_fallback: ProposerFallback<T>,
        slot: Slot,
        graffiti: Option<Graffiti>,
        validator_pubkey: &PublicKeyBytes,
        unsigned_block: UnsignedBlock<S::E>,
    ) -> Result<(), BlockError> {
        let signing_timer = validator_metrics::start_timer(&validator_metrics::BLOCK_SIGNING_TIMES);

        let res = self
            .validator_store
            .sign_block(*validator_pubkey, unsigned_block, slot)
            .await;

        let signed_block = match res {
            Ok(block) => block,
            Err(ValidatorStoreError::UnknownPubkey(pubkey)) => {
                // A pubkey can be missing when a validator was recently removed
                // via the API.
                warn!(
                    info = "a validator may have recently been removed from this VC",
                    ?pubkey,
                    ?slot,
                    "Missing pubkey for block"
                );
                return Ok(());
            }
            Err(e) => {
                return Err(BlockError::Recoverable(format!(
                    "Unable to sign block: {:?}",
                    e
                )));
            }
        };

        let signing_time_ms =
            Duration::from_secs_f64(signing_timer.map_or(0.0, |t| t.stop_and_record())).as_millis();

        info!(
            slot = slot.as_u64(),
            signing_time_ms = signing_time_ms,
            "Publishing signed block"
        );

        // Publish block with first available beacon node.
        //
        // Try the proposer nodes first, since we've likely gone to efforts to
        // protect them from DoS attacks and they're most likely to successfully
        // publish a block.
        proposer_fallback
            .request_proposers_first(|beacon_node| async {
                self.publish_signed_block_contents(&signed_block, beacon_node)
                    .await
            })
            .await?;

        let metadata = BlockMetadata::from(&signed_block);
        info!(
            block_type = ?metadata.block_type,
            deposits = metadata.num_deposits,
            attestations = metadata.num_attestations,
            graffiti = ?graffiti.map(|g| g.as_utf8_lossy()),
            slot = metadata.slot.as_u64(),
            "Successfully published block"
        );
        Ok(())
    }

    async fn publish_block(
        self,
        slot: Slot,
        validator_pubkey: PublicKeyBytes,
        builder_boost_factor: Option<u64>,
    ) -> Result<(), BlockError> {
        let _timer = validator_metrics::start_timer_vec(
            &validator_metrics::BLOCK_SERVICE_TIMES,
            &[validator_metrics::BEACON_BLOCK],
        );

        let randao_reveal = match self
            .validator_store
            .randao_reveal(validator_pubkey, slot.epoch(S::E::slots_per_epoch()))
            .await
        {
            Ok(signature) => signature.into(),
            Err(ValidatorStoreError::UnknownPubkey(pubkey)) => {
                // A pubkey can be missing when a validator was recently removed
                // via the API.
                warn!(
                    info = "a validator may have recently been removed from this VC",
                    ?pubkey,
                    ?slot,
                    "Missing pubkey for block randao"
                );
                return Ok(());
            }
            Err(e) => {
                return Err(BlockError::Recoverable(format!(
                    "Unable to produce randao reveal signature: {:?}",
                    e
                )));
            }
        };

        let graffiti = determine_graffiti(
            &validator_pubkey,
            self.graffiti_file.clone(),
            self.validator_store.graffiti(&validator_pubkey),
            self.graffiti,
        );

        let randao_reveal_ref = &randao_reveal;
        let self_ref = &self;
        let proposer_index = self.validator_store.validator_index(&validator_pubkey);
        let proposer_fallback = ProposerFallback {
            beacon_nodes: self.beacon_nodes.clone(),
            proposer_nodes: self.proposer_nodes.clone(),
        };

        info!(slot = slot.as_u64(), "Requesting unsigned block");

        // Request block from first responsive beacon node.
        //
        // Try the proposer nodes last, since it's likely that they don't have a
        // great view of attestations on the network.
        let unsigned_block = proposer_fallback
            .request_proposers_last(|beacon_node| async move {
                let _get_timer = validator_metrics::start_timer_vec(
                    &validator_metrics::BLOCK_SERVICE_TIMES,
                    &[validator_metrics::BEACON_BLOCK_HTTP_GET],
                );
                Self::get_validator_block(
                    &beacon_node,
                    slot,
                    randao_reveal_ref,
                    graffiti,
                    proposer_index,
                    builder_boost_factor,
                )
                .await
                .map_err(|e| {
                    BlockError::Recoverable(format!(
                        "Error from beacon node when producing block: {:?}",
                        e
                    ))
                })
            })
            .await?;

        self_ref
            .sign_and_publish_block(
                proposer_fallback,
                slot,
                graffiti,
                &validator_pubkey,
                unsigned_block,
            )
            .await?;

        Ok(())
    }

    async fn publish_signed_block_contents(
        &self,
        signed_block: &SignedBlock<S::E>,
        beacon_node: BeaconNodeHttpClient,
    ) -> Result<(), BlockError> {
        match signed_block {
            SignedBlock::Full(signed_block) => {
                let _post_timer = validator_metrics::start_timer_vec(
                    &validator_metrics::BLOCK_SERVICE_TIMES,
                    &[validator_metrics::BEACON_BLOCK_HTTP_POST],
                );
                beacon_node
                    .post_beacon_blocks_v2_ssz(signed_block, None)
                    .await
                    .map(|_| ())
                    .or_else(|e| {
                        handle_block_post_error(e, signed_block.signed_block().message().slot())
                    })?
            }
            SignedBlock::Blinded(signed_block) => {
                let _post_timer = validator_metrics::start_timer_vec(
                    &validator_metrics::BLOCK_SERVICE_TIMES,
                    &[validator_metrics::BLINDED_BEACON_BLOCK_HTTP_POST],
                );

                beacon_node
                    .post_beacon_blinded_blocks_v2_ssz(signed_block, None)
                    .await
                    .map(|_| ())
                    .or_else(|e| handle_block_post_error(e, signed_block.message().slot()))?;
            }
        }
        Ok::<_, BlockError>(())
    }

    async fn get_validator_block(
        beacon_node: &BeaconNodeHttpClient,
        slot: Slot,
        randao_reveal_ref: &SignatureBytes,
        graffiti: Option<Graffiti>,
        proposer_index: Option<u64>,
        builder_boost_factor: Option<u64>,
    ) -> Result<UnsignedBlock<S::E>, BlockError> {
        let block_response = match beacon_node
            .get_validator_blocks_v3_ssz::<S::E>(
                slot,
                randao_reveal_ref,
                graffiti.as_ref(),
                builder_boost_factor,
            )
            .await
        {
            Ok((ssz_block_response, _)) => ssz_block_response,
            Err(e) => {
                warn!(
                    slot = slot.as_u64(),
                    error = %e,
                    "Beacon node does not support SSZ in block production, falling back to JSON"
                );

                let (json_block_response, _) = beacon_node
                    .get_validator_blocks_v3::<S::E>(
                        slot,
                        randao_reveal_ref,
                        graffiti.as_ref(),
                        builder_boost_factor,
                    )
                    .await
                    .map_err(|e| {
                        BlockError::Recoverable(format!(
                            "Error from beacon node when producing block: {:?}",
                            e
                        ))
                    })?;

                // Extract ProduceBlockV3Response (data field of the struct ForkVersionedResponse)
                json_block_response.data
            }
        };

        let (block_proposer, unsigned_block) = match block_response {
            eth2::types::ProduceBlockV3Response::Full(block) => {
                (block.block().proposer_index(), UnsignedBlock::Full(block))
            }
            eth2::types::ProduceBlockV3Response::Blinded(block) => {
                (block.proposer_index(), UnsignedBlock::Blinded(block))
            }
        };

        info!(slot = slot.as_u64(), "Received unsigned block");
        if proposer_index != Some(block_proposer) {
            return Err(BlockError::Recoverable(
                "Proposer index does not match block proposer. Beacon chain re-orged".to_string(),
            ));
        }

        Ok::<_, BlockError>(unsigned_block)
    }
}

/// Wrapper for values we want to log about a block we signed, for easy extraction from the possible
/// variants.
struct BlockMetadata {
    block_type: BlockType,
    slot: Slot,
    num_deposits: usize,
    num_attestations: usize,
}

impl<E: EthSpec> From<&SignedBlock<E>> for BlockMetadata {
    fn from(value: &SignedBlock<E>) -> Self {
        match value {
            SignedBlock::Full(block) => BlockMetadata {
                block_type: BlockType::Full,
                slot: block.signed_block().message().slot(),
                num_deposits: block.signed_block().message().body().deposits().len(),
                num_attestations: block.signed_block().message().body().attestations_len(),
            },
            SignedBlock::Blinded(block) => BlockMetadata {
                block_type: BlockType::Blinded,
                slot: block.message().slot(),
                num_deposits: block.message().body().deposits().len(),
                num_attestations: block.message().body().attestations_len(),
            },
        }
    }
}

fn handle_block_post_error(err: eth2::Error, slot: Slot) -> Result<(), BlockError> {
    // Handle non-200 success codes.
    if let Some(status) = err.status() {
        if status == StatusCode::ACCEPTED {
            info!(
                %slot,
                status_code = status.as_u16(),
                "Block is already known to BN or might be invalid"
            );
            return Ok(());
        } else if status.is_success() {
            debug!(
                %slot,
                status_code = status.as_u16(),
                "Block published with non-standard success code"
            );
            return Ok(());
        }
    }
    Err(BlockError::Irrecoverable(format!(
        "Error from beacon node when publishing block: {err:?}",
    )))
}
