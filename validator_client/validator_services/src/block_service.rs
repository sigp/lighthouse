use beacon_node_fallback::{ApiTopic, BeaconNodeFallback, Error as FallbackError, Errors};
use bls::SignatureBytes;
use eth2::types::{FullBlockContents, PublishBlockRequest};
use eth2::{BeaconNodeHttpClient, StatusCode};
use graffiti_file::{determine_graffiti, GraffitiFile};
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
use types::{
    BlindedBeaconBlock, BlockType, ChainSpec, EthSpec, Graffiti, PublicKeyBytes,
    SignedBlindedBeaconBlock, Slot,
};
use validator_store::{Error as ValidatorStoreError, ValidatorStore};

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
    chain_spec: Option<ChainSpec>,
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
        if let Some(proposer_nodes) = &self.proposer_nodes {
            if proposer_nodes
                .request(ApiTopic::Blocks, func.clone())
                .await
                .is_ok()
            {
                return Ok(());
            }
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
    chain_spec: ChainSpec,
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
    pub fn start_update_service<E: EthSpec>(
        self,
        mut notification_rx: mpsc::Receiver<BlockServiceNotification>,
    ) -> Result<(), String> {
        info!("Block production service started");

        let executor = self.inner.executor.clone();

        executor.spawn(
            async move {
                while let Some(notif) = notification_rx.recv().await {
                    self.do_update::<E>(notif).await.ok();
                }
                debug!("Block service shutting down");
            },
            "block_service",
        );

        Ok(())
    }

    /// Attempt to produce a block for any block producers in the `ValidatorStore`.
    async fn do_update<E: EthSpec>(
        &self,
        notification: BlockServiceNotification,
    ) -> Result<(), ()> {
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
            let builder_boost_factor = self.get_builder_boost_factor(&validator_pubkey);
            let service = self.clone();
            self.inner.executor.spawn(
                async move {
                    let result = service
                        .publish_block::<E>(slot, validator_pubkey, builder_boost_factor)
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
    async fn sign_and_publish_block<E: EthSpec>(
        &self,
        proposer_fallback: ProposerFallback<T>,
        slot: Slot,
        graffiti: Option<Graffiti>,
        validator_pubkey: &PublicKeyBytes,
        unsigned_block: UnsignedBlock<E>,
    ) -> Result<(), BlockError> {
        let signing_timer = validator_metrics::start_timer(&validator_metrics::BLOCK_SIGNING_TIMES);

        let res = match unsigned_block {
            UnsignedBlock::Full(block_contents) => {
                let (block, maybe_blobs) = block_contents.deconstruct();
                self.validator_store
                    .sign_block(*validator_pubkey, block, slot)
                    .await
                    .map(|b| SignedBlock::Full(PublishBlockRequest::new(Arc::new(b), maybe_blobs)))
            }
            UnsignedBlock::Blinded(block) => self
                .validator_store
                .sign_block(*validator_pubkey, block, slot)
                .await
                .map(Arc::new)
                .map(SignedBlock::Blinded),
        };

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
                )))
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

        info!(
            block_type = ?signed_block.block_type(),
            deposits = signed_block.num_deposits(),
            attestations = signed_block.num_attestations(),
            graffiti = ?graffiti.map(|g| g.as_utf8_lossy()),
            slot = signed_block.slot().as_u64(),
            "Successfully published block"
        );
        Ok(())
    }

    async fn publish_block<E: EthSpec>(
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
            .randao_reveal::<E>(validator_pubkey, slot.epoch(E::slots_per_epoch()))
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
                )))
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
                Self::get_validator_block::<E>(
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

    async fn publish_signed_block_contents<E: EthSpec>(
        &self,
        signed_block: &SignedBlock<E>,
        beacon_node: BeaconNodeHttpClient,
    ) -> Result<(), BlockError> {
        let slot = signed_block.slot();
        match signed_block {
            SignedBlock::Full(signed_block) => {
                let _post_timer = validator_metrics::start_timer_vec(
                    &validator_metrics::BLOCK_SERVICE_TIMES,
                    &[validator_metrics::BEACON_BLOCK_HTTP_POST],
                );
                beacon_node
                    .post_beacon_blocks_v2_ssz(signed_block, None)
                    .await
                    .or_else(|e| handle_block_post_error(e, slot))?
            }
            SignedBlock::Blinded(signed_block) => {
                let _post_timer = validator_metrics::start_timer_vec(
                    &validator_metrics::BLOCK_SERVICE_TIMES,
                    &[validator_metrics::BLINDED_BEACON_BLOCK_HTTP_POST],
                );
                beacon_node
                    .post_beacon_blinded_blocks_v2_ssz(signed_block, None)
                    .await
                    .or_else(|e| handle_block_post_error(e, slot))?
            }
        }
        Ok::<_, BlockError>(())
    }

    async fn get_validator_block<E: EthSpec>(
        beacon_node: &BeaconNodeHttpClient,
        slot: Slot,
        randao_reveal_ref: &SignatureBytes,
        graffiti: Option<Graffiti>,
        proposer_index: Option<u64>,
        builder_boost_factor: Option<u64>,
    ) -> Result<UnsignedBlock<E>, BlockError> {
        let (block_response, _) = beacon_node
            .get_validator_blocks_v3::<E>(
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

        let unsigned_block = match block_response.data {
            eth2::types::ProduceBlockV3Response::Full(block) => UnsignedBlock::Full(block),
            eth2::types::ProduceBlockV3Response::Blinded(block) => UnsignedBlock::Blinded(block),
        };

        info!(slot = slot.as_u64(), "Received unsigned block");
        if proposer_index != Some(unsigned_block.proposer_index()) {
            return Err(BlockError::Recoverable(
                "Proposer index does not match block proposer. Beacon chain re-orged".to_string(),
            ));
        }

        Ok::<_, BlockError>(unsigned_block)
    }

    /// Returns the builder boost factor of the given public key.
    /// The priority order for fetching this value is:
    ///
    /// 1. validator_definitions.yml
    /// 2. process level flag
    fn get_builder_boost_factor(&self, validator_pubkey: &PublicKeyBytes) -> Option<u64> {
        // Apply per validator configuration first.
        let validator_builder_boost_factor = self
            .validator_store
            .determine_validator_builder_boost_factor(validator_pubkey);

        // Fallback to process-wide configuration if needed.
        let maybe_builder_boost_factor = validator_builder_boost_factor.or_else(|| {
            self.validator_store
                .determine_default_builder_boost_factor()
        });

        if let Some(builder_boost_factor) = maybe_builder_boost_factor {
            // if builder boost factor is set to 100 it should be treated
            // as None to prevent unnecessary calculations that could
            // lead to loss of information.
            if builder_boost_factor == 100 {
                return None;
            }
            return Some(builder_boost_factor);
        }

        None
    }
}

pub enum UnsignedBlock<E: EthSpec> {
    Full(FullBlockContents<E>),
    Blinded(BlindedBeaconBlock<E>),
}

impl<E: EthSpec> UnsignedBlock<E> {
    pub fn proposer_index(&self) -> u64 {
        match self {
            UnsignedBlock::Full(block) => block.block().proposer_index(),
            UnsignedBlock::Blinded(block) => block.proposer_index(),
        }
    }
}

#[derive(Debug)]
pub enum SignedBlock<E: EthSpec> {
    Full(PublishBlockRequest<E>),
    Blinded(Arc<SignedBlindedBeaconBlock<E>>),
}

impl<E: EthSpec> SignedBlock<E> {
    pub fn block_type(&self) -> BlockType {
        match self {
            SignedBlock::Full(_) => BlockType::Full,
            SignedBlock::Blinded(_) => BlockType::Blinded,
        }
    }
    pub fn slot(&self) -> Slot {
        match self {
            SignedBlock::Full(block) => block.signed_block().message().slot(),
            SignedBlock::Blinded(block) => block.message().slot(),
        }
    }
    pub fn num_deposits(&self) -> usize {
        match self {
            SignedBlock::Full(block) => block.signed_block().message().body().deposits().len(),
            SignedBlock::Blinded(block) => block.message().body().deposits().len(),
        }
    }
    pub fn num_attestations(&self) -> usize {
        match self {
            SignedBlock::Full(block) => block.signed_block().message().body().attestations_len(),
            SignedBlock::Blinded(block) => block.message().body().attestations_len(),
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
