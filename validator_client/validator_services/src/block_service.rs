use beacon_node_fallback::{ApiTopic, BeaconNodeFallback, Error as FallbackError, Errors};
use bls::PublicKeyBytes;
use eth2::BeaconNodeHttpClient;
use eth2::types::GraffitiPolicy;
use graffiti_file::{GraffitiFile, determine_graffiti};
use logging::crit;
use reqwest::StatusCode;
use slot_clock::SlotClock;
use std::fmt::Debug;
use std::future::Future;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::mpsc;
use tracing::{Instrument, debug, error, info, info_span, instrument, trace, warn};
use types::{BlockType, ChainSpec, EthSpec, Graffiti, Hash256, Slot};
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
    graffiti_policy: Option<GraffitiPolicy>,
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
            graffiti_policy: None,
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

    pub fn graffiti_policy(mut self, graffiti_policy: Option<GraffitiPolicy>) -> Self {
        self.graffiti_policy = graffiti_policy;
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
                graffiti_policy: self.graffiti_policy,
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
    graffiti_policy: Option<GraffitiPolicy>,
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
                        .get_validator_block_and_publish_block(slot, validator_pubkey, builder_boost_factor)
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
    #[instrument(skip_all, fields(%slot, ?validator_pubkey))]
    async fn sign_and_publish_block(
        &self,
        proposer_fallback: &ProposerFallback<T>,
        slot: Slot,
        graffiti: Option<Graffiti>,
        validator_pubkey: &PublicKeyBytes,
        unsigned_block: UnsignedBlock<S::E>,
    ) -> Result<(), BlockError> {
        let signing_timer = validator_metrics::start_timer(&validator_metrics::BLOCK_SIGNING_TIMES);

        let res = self
            .validator_store
            .sign_block(*validator_pubkey, unsigned_block, slot)
            .instrument(info_span!("sign_block"))
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

    #[instrument(
        name = "lh_block_proposal_duty_cycle",
        skip_all,
        fields(%slot, ?validator_pubkey)
    )]
    async fn get_validator_block_and_publish_block(
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

        // Check if Gloas fork is active at this slot
        let fork_name = self_ref.chain_spec.fork_name_at_slot::<S::E>(slot);

        let (block_proposer, unsigned_block) = if fork_name.gloas_enabled() {
            // Use V4 block production for Gloas
            // Request an SSZ block from all beacon nodes in order, returning on the first successful response.
            // If all nodes fail, run a second pass falling back to JSON.
            let ssz_block_response = proposer_fallback
                .request_proposers_last(|beacon_node| async move {
                    let _get_timer = validator_metrics::start_timer_vec(
                        &validator_metrics::BLOCK_SERVICE_TIMES,
                        &[validator_metrics::BEACON_BLOCK_HTTP_GET],
                    );
                    beacon_node
                        .get_validator_blocks_v4_ssz::<S::E>(
                            slot,
                            randao_reveal_ref,
                            graffiti.as_ref(),
                            Some(false),
                            builder_boost_factor,
                            self_ref.graffiti_policy,
                        )
                        .await
                })
                .await;

            let block_response = match ssz_block_response {
                Ok((ssz_block_response, _metadata)) => ssz_block_response,
                Err(e) => {
                    warn!(
                        slot = slot.as_u64(),
                        error = %e,
                        "SSZ V4 block production failed, falling back to JSON"
                    );

                    proposer_fallback
                        .request_proposers_last(|beacon_node| async move {
                            let _get_timer = validator_metrics::start_timer_vec(
                                &validator_metrics::BLOCK_SERVICE_TIMES,
                                &[validator_metrics::BEACON_BLOCK_HTTP_GET],
                            );
                            let (json_block_response, _metadata) = beacon_node
                                .get_validator_blocks_v4::<S::E>(
                                    slot,
                                    randao_reveal_ref,
                                    graffiti.as_ref(),
                                    Some(false),
                                    builder_boost_factor,
                                    self_ref.graffiti_policy,
                                )
                                .await
                                .map_err(|e| {
                                    BlockError::Recoverable(format!(
                                        "Error from beacon node when producing block: {:?}",
                                        e
                                    ))
                                })?;

                            Ok(json_block_response.data)
                        })
                        .await
                        .map_err(BlockError::from)?
                }
            };

            // Gloas blocks don't have blobs (they're in the execution layer)
            let block_contents = eth2::types::FullBlockContents::Block(block_response);
            (
                block_contents.block().proposer_index(),
                UnsignedBlock::Full(block_contents),
            )
        } else {
            // Use V3 block production for pre-Gloas forks
            // Request an SSZ block from all beacon nodes in order, returning on the first successful response.
            // If all nodes fail, run a second pass falling back to JSON.
            //
            // Proposer nodes will always be tried last during each pass since it's likely that they don't have a
            // great view of attestations on the network.
            let ssz_block_response = proposer_fallback
                .request_proposers_last(|beacon_node| async move {
                    let _get_timer = validator_metrics::start_timer_vec(
                        &validator_metrics::BLOCK_SERVICE_TIMES,
                        &[validator_metrics::BEACON_BLOCK_HTTP_GET],
                    );
                    beacon_node
                        .get_validator_blocks_v3_ssz::<S::E>(
                            slot,
                            randao_reveal_ref,
                            graffiti.as_ref(),
                            builder_boost_factor,
                            self_ref.graffiti_policy,
                        )
                        .await
                })
                .await;

            let block_response = match ssz_block_response {
                Ok((ssz_block_response, _metadata)) => ssz_block_response,
                Err(e) => {
                    warn!(
                        slot = slot.as_u64(),
                        error = %e,
                        "SSZ block production failed, falling back to JSON"
                    );

                    proposer_fallback
                        .request_proposers_last(|beacon_node| async move {
                            let _get_timer = validator_metrics::start_timer_vec(
                                &validator_metrics::BLOCK_SERVICE_TIMES,
                                &[validator_metrics::BEACON_BLOCK_HTTP_GET],
                            );
                            let (json_block_response, _metadata) = beacon_node
                                .get_validator_blocks_v3::<S::E>(
                                    slot,
                                    randao_reveal_ref,
                                    graffiti.as_ref(),
                                    builder_boost_factor,
                                    self_ref.graffiti_policy,
                                )
                                .await
                                .map_err(|e| {
                                    BlockError::Recoverable(format!(
                                        "Error from beacon node when producing block: {:?}",
                                        e
                                    ))
                                })?;

                            Ok(json_block_response.data)
                        })
                        .await
                        .map_err(BlockError::from)?
                }
            };

            match block_response {
                eth2::types::ProduceBlockV3Response::Full(block) => {
                    (block.block().proposer_index(), UnsignedBlock::Full(block))
                }
                eth2::types::ProduceBlockV3Response::Blinded(block) => {
                    (block.proposer_index(), UnsignedBlock::Blinded(block))
                }
            }
        };

        info!(slot = slot.as_u64(), "Received unsigned block");
        if proposer_index != Some(block_proposer) {
            return Err(BlockError::Recoverable(
                "Proposer index does not match block proposer. Beacon chain re-orged".to_string(),
            ));
        }

        // Capture before `sign_and_publish_block` moves `unsigned_block`.
        let produced_block_root = fork_name
            .gloas_enabled()
            .then(|| unsigned_block.block_root());

        self_ref
            .sign_and_publish_block(
                &proposer_fallback,
                slot,
                graffiti,
                &validator_pubkey,
                unsigned_block,
            )
            .await?;

        // TODO(gloas) we only need to fetch, sign and publish the envelope in the local building case.
        // Right now we always default to local building. Once we implement trustless/trusted builder logic
        // we should check the bid for index == BUILDER_INDEX_SELF_BUILD
        if let Some(beacon_block_root) = produced_block_root {
            self_ref
                .fetch_sign_and_publish_payload_envelope(
                    &proposer_fallback,
                    slot,
                    beacon_block_root,
                    &validator_pubkey,
                )
                .await?;
        }

        Ok(())
    }

    /// Fetch, sign, and publish the execution payload envelope for Gloas.
    /// This should be called after the block has been published.
    ///
    /// TODO(gloas): For multi-BN setups, we need to track which beacon node produced the block
    /// and fetch the envelope from that same node. The envelope is cached per-BN,
    /// so fetching from a different BN than the one that built the block will fail.
    /// See: https://github.com/sigp/lighthouse/pull/8313
    #[instrument(skip_all)]
    async fn fetch_sign_and_publish_payload_envelope(
        &self,
        _proposer_fallback: &ProposerFallback<T>,
        slot: Slot,
        beacon_block_root: Hash256,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<(), BlockError> {
        info!(
            slot = slot.as_u64(),
            %beacon_block_root,
            "Fetching execution payload envelope"
        );

        // Fetch the envelope from the beacon node.
        let envelope = self
            .beacon_nodes
            .first_success(|beacon_node| async move {
                beacon_node
                    .get_validator_execution_payload_envelopes_ssz::<S::E>(slot, beacon_block_root)
                    .await
                    .map_err(|e| {
                        BlockError::Recoverable(format!(
                            "Error fetching execution payload envelope: {:?}",
                            e
                        ))
                    })
            })
            .await?;

        info!(
            slot = slot.as_u64(),
            beacon_block_root = %envelope.beacon_block_root,
            "Received execution payload envelope, signing"
        );

        // Sign the envelope
        let signed_envelope = self
            .validator_store
            .sign_execution_payload_envelope(*validator_pubkey, envelope)
            .await
            .map_err(|e| {
                BlockError::Recoverable(format!(
                    "Error signing execution payload envelope: {:?}",
                    e
                ))
            })?;

        info!(
            slot = slot.as_u64(),
            "Signed execution payload envelope, publishing"
        );

        let fork_name = self.chain_spec.fork_name_at_slot::<S::E>(slot);

        // Publish the signed envelope
        // TODO(gloas): Use proposer_fallback once multi-BN is supported.
        self.beacon_nodes
            .first_success(|beacon_node| {
                let signed_envelope = signed_envelope.clone();
                async move {
                    beacon_node
                        .post_beacon_execution_payload_envelopes_ssz(
                            &signed_envelope,
                            fork_name,
                            None,
                        )
                        .await
                        .map_err(|e| {
                            BlockError::Recoverable(format!(
                                "Error publishing execution payload envelope: {:?}",
                                e
                            ))
                        })
                }
            })
            .await?;

        info!(
            slot = slot.as_u64(),
            beacon_block_root = %signed_envelope.message.beacon_block_root,
            "Successfully published signed execution payload envelope"
        );

        Ok(())
    }

    #[instrument(skip_all)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use slot_clock::ManualSlotClock;
    use std::time::Duration;
    use types::{BeaconBlock, ExecutionPayloadEnvelope, ForkName, Slot};
    use validator_test_rig::validator_client_harness::{S, ValidatorClientHarness};

    struct TestHarness {
        harness: ValidatorClientHarness,
        service: BlockService<S, ManualSlotClock>,
    }

    impl TestHarness {
        async fn new_with_validators(num_validators: usize) -> Self {
            let harness = ValidatorClientHarness::new(num_validators).await;

            // advance the time to Slot 1
            harness
                .slot_clock
                .advance_time(harness.spec.get_slot_duration());

            let service = BlockServiceBuilder::new()
                .validator_store(harness.validator_store.clone())
                .slot_clock(harness.slot_clock.clone())
                .beacon_nodes(harness.beacon_nodes.clone())
                .executor(harness.test_runtime.task_executor.clone())
                .chain_spec(harness.spec.clone())
                .build()
                .unwrap();

            Self { harness, service }
        }
    }

    #[tokio::test]
    async fn test_do_update() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let validator_pubkey = test_harness.harness.pubkeys[0];

        // Simulate a scenario where the slot is different form the notification slot
        // slot_clock is at Slot 1 (defined in TestHarness), but the notification slot is at Slot 2
        let different_notification_slot = Slot::new(2);
        let block = BeaconBlock::empty(&test_harness.harness.spec);

        let different_notification = BlockServiceNotification {
            slot: different_notification_slot,
            block_proposers: vec![validator_pubkey],
        };

        let mock_different_slot = test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_blocks_v4_ssz(&block, ForkName::Gloas, different_notification_slot);

        test_harness
            .service
            .do_update(different_notification)
            .await
            .unwrap();

        // For slot that is different from the notification slot, do_update should return early and no BN is called
        mock_different_slot.expect(0).assert();

        // Simulate a scenario where the slot is the same as the notification slot
        let same_notification_slot = Slot::new(1);

        let same_notification = BlockServiceNotification {
            slot: same_notification_slot,
            block_proposers: vec![validator_pubkey],
        };

        let mock_same_slot = test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_blocks_v4_ssz(&block, ForkName::Gloas, same_notification_slot);

        test_harness
            .service
            .do_update(same_notification)
            .await
            .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        // .matched() becomes true if mock_same_slot has been hit once
        // mock_same_slot.matched() will be false when the spawned thread for get_validator_block_and_publish_block has not been created
        // (therefore mock_same_slot hasn't been called/hit)
        // Once a spawned thread is created, the while loop becomes false and exits the loop
        // This ensures that a spawned thread is created for get_validator_block_and_publish_block
        while !mock_same_slot.matched() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // When the slot is the same as notification slot, the flow to produce and publish block proceeds normally
        // so the BN should be called once (in this case it succeeded on the first call)
        mock_same_slot.expect(1).assert();
    }

    #[tokio::test]
    async fn get_validator_block_and_publish_block_succeeds() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let slot = Slot::new(1);
        let validator_pubkey = test_harness.harness.pubkeys[0];
        let block = BeaconBlock::empty(&test_harness.harness.spec);
        let envelope = ExecutionPayloadEnvelope::empty();

        test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_blocks_v4_ssz(&block, ForkName::Gloas, slot);
        let mock_post_block = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_blocks_v2_ssz(ForkName::Gloas);
        test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_execution_payload_envelope_ssz(
                &envelope,
                slot,
                block.canonical_root(),
            );
        let mock_post_envelope = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_execution_payload_envelope_ssz();

        let result = test_harness
            .service
            .clone()
            .get_validator_block_and_publish_block(slot, validator_pubkey, None)
            .await;

        assert!(
            result.is_ok(),
            "Block production failed: {:?}",
            result.err()
        );

        // Both mock BN only being hit once, as it is successful on the first call
        mock_post_block.expect(1).assert();
        mock_post_envelope.expect(1).assert();

        let received_blocks = test_harness
            .harness
            .mock_beacon_node_1
            .received_full_blocks
            .lock()
            .unwrap();
        assert_eq!(received_blocks.len(), 1, "Expected one published block");

        let received_envelopes = test_harness
            .harness
            .mock_beacon_node_1
            .execution_payload_envelope
            .lock()
            .unwrap();
        assert_eq!(received_envelopes.len(), 1, "Expected one envelope");
    }

    #[tokio::test]
    async fn get_validator_block_and_publish_block_fails() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let slot = Slot::new(1);
        let validator_pubkey = test_harness.harness.pubkeys[0];

        // Simulate both beacon nodes return error for get_validator_blocks
        // there is no JSON fallback in this case, so get_validator_blocks should fail
        let mock_bn_1 = test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_blocks_v4_ssz_error(slot);
        let mock_bn_2 = test_harness
            .harness
            .mock_beacon_node_2
            .mock_get_validator_blocks_v4_ssz_error(slot);

        let mock_post_block = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_blocks_v2_ssz(ForkName::Gloas);
        let mock_post_envelope = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_execution_payload_envelope_ssz();

        let result = test_harness
            .service
            .clone()
            .get_validator_block_and_publish_block(slot, validator_pubkey, None)
            .await;

        let Err(BlockError::Recoverable(msg)) = result else {
            panic!("Expected Recoverable block production error, got: {result:?}");
        };
        // When both beacon nodes failed in get_validator_blocks (both SSZ and JSON failed), we should get the error below
        assert!(msg.contains("Error from beacon node when producing block"),);

        // first_success does 2 passes, so each BN is hit twice for SSZ
        mock_bn_1.expect(2).assert();
        mock_bn_2.expect(2).assert();

        // Block was never published since production failed
        mock_post_block.expect(0).assert();
        mock_post_envelope.expect(0).assert();
    }

    #[tokio::test]
    async fn get_validator_block_ssz_fails_fallback_to_json() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let slot = Slot::new(1);
        let validator_pubkey = test_harness.harness.pubkeys[0];
        let block = BeaconBlock::empty(&test_harness.harness.spec);

        // mock_ssz returns 500 to simulate BN does not support SSZ, so that it fallbacks to mock_json
        let mock_ssz = test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_blocks_v4_ssz_error(slot);
        let mock_json = test_harness
            .harness
            .mock_beacon_node_2
            .mock_get_validator_blocks_v4(&block, ForkName::Gloas, slot);

        let _result = test_harness
            .service
            .clone()
            .get_validator_block_and_publish_block(slot, validator_pubkey, None)
            .await;

        // first_success tries 2 passes on mock_ssz, both time failed
        mock_ssz.expect(2).assert();

        // When SSZ fails, it fallbacks to JSON and should succeed on first call on mock_json.
        mock_json.expect(1).assert();
    }

    #[tokio::test]
    async fn get_validator_execution_payload_envelope_ssz_fails() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let slot = Slot::new(1);
        let validator_pubkey = test_harness.harness.pubkeys[0];

        // Both beacon nodes return error for get_validator_execution_payload_envelope_ssz
        test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_execution_payload_envelope_ssz_error(slot, Hash256::default());
        test_harness
            .harness
            .mock_beacon_node_2
            .mock_get_validator_execution_payload_envelope_ssz_error(slot, Hash256::default());

        let mock_post_envelope = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_execution_payload_envelope_ssz();

        let proposer_fallback = ProposerFallback {
            beacon_nodes: test_harness.service.beacon_nodes.clone(),
            proposer_nodes: test_harness.service.proposer_nodes.clone(),
        };

        let result = test_harness
            .service
            .fetch_sign_and_publish_payload_envelope(
                &proposer_fallback,
                slot,
                Hash256::default(),
                &validator_pubkey,
            )
            .await;

        let Err(BlockError::Recoverable(msg)) = result else {
            panic!("Expected Recoverable error, got: {result:?}");
        };
        // When get_validator_execution_payload_envelope_ssz failed, we should get the error below
        assert!(msg.contains("Error fetching execution payload envelope"));

        // Since get_validator_execution_payload_envelope_ssz failed, the BN shouldn't be called to publish the envelope
        mock_post_envelope.expect(0).assert();
    }

    #[tokio::test]
    async fn post_beacon_execution_payload_envelope_ssz_fails() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let slot = Slot::new(1);
        let validator_pubkey = test_harness.harness.pubkeys[0];
        let envelope = ExecutionPayloadEnvelope::empty();

        test_harness
            .harness
            .mock_beacon_node_1
            .mock_get_validator_execution_payload_envelope_ssz(&envelope, slot, Hash256::default());

        // Both beacon nodes return error for post_beacon_execution_payload_envelope_ssz
        let mock_post_envelope_1 = test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_beacon_execution_payload_envelope_ssz_error();
        let mock_post_envelope_2 = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_beacon_execution_payload_envelope_ssz_error();

        let proposer_fallback = ProposerFallback {
            beacon_nodes: test_harness.service.beacon_nodes.clone(),
            proposer_nodes: test_harness.service.proposer_nodes.clone(),
        };

        let result = test_harness
            .service
            .fetch_sign_and_publish_payload_envelope(
                &proposer_fallback,
                slot,
                Hash256::default(),
                &validator_pubkey,
            )
            .await;

        let Err(BlockError::Recoverable(msg)) = result else {
            panic!("Expected Recoverable error, got: {result:?}");
        };
        // When post_beacon_execution_payload_envelope_ssz failed, we should get the error below
        assert!(msg.contains("Error publishing execution payload envelope"));

        // first_success tries 2 times, so each BN is hit twice
        mock_post_envelope_1.expect(2).assert();
        mock_post_envelope_2.expect(2).assert();
    }
}
