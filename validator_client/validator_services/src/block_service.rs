use crate::request_auth_cache::RequestAuthCache;
use beacon_node_fallback::{ApiTopic, BeaconNodeFallback, Error as FallbackError, Errors};
use bls::PublicKeyBytes;
use builder_store::BuilderStore;
use eth2::BeaconNodeHttpClient;
use eth2::types::{
    BlockAndEnvelope, GraffitiPolicy, ProduceBlockV4Response,
    SignedExecutionPayloadEnvelopeContents,
};
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
use tree_hash::TreeHash;
use types::{
    BeaconBlock, BlobsList, BlockType, ChainSpec, EthSpec, ExecutionPayloadEnvelope, ForkName,
    Graffiti, Hash256, KzgProofs, Slot, consts::gloas::BUILDER_INDEX_SELF_BUILD,
};
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
    configured_builders: Option<BuilderStore>,
    request_auth_cache: Option<RequestAuthCache>,
    stateless_block_production: bool,
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
            configured_builders: None,
            request_auth_cache: None,
            stateless_block_production: false,
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

    pub fn configured_builders(mut self, configured_builders: BuilderStore) -> Self {
        self.configured_builders = Some(configured_builders);
        self
    }

    pub fn request_auth_cache(mut self, request_auth_cache: RequestAuthCache) -> Self {
        self.request_auth_cache = Some(request_auth_cache);
        self
    }

    pub fn stateless_block_production(mut self, enabled: bool) -> Self {
        self.stateless_block_production = enabled;
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
                configured_builders: self
                    .configured_builders
                    .ok_or("Cannot build BlockService without configured_builders")?,
                request_auth_cache: self
                    .request_auth_cache
                    .ok_or("Cannot build BlockService without request_auth_cache")?,
                stateless_block_production: self.stateless_block_production,
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
    /// The configured builders to resolve into a `BuilderConfig` when producing a Gloas block.
    configured_builders: BuilderStore,
    /// Caches the per-(slot, proposer, auth_data) request-auth signatures reused when resolving the
    /// builder config.
    request_auth_cache: RequestAuthCache,
    /// Produce Gloas blocks with `include_payload=true` and publish the self-built envelope from
    /// the response, rather than fetching it from the beacon node that built the block.
    stateless_block_production: bool,
}

/// The envelope, KZG proofs and blobs returned with a self-built block when `include_payload=true`.
struct LocalPayloadContents<E: EthSpec> {
    envelope: ExecutionPayloadEnvelope<E>,
    kzg_proofs: KzgProofs<E>,
    blobs: BlobsList<E>,
}

/// What to do about the execution payload envelope once the block is published.
enum EnvelopeStep<E: EthSpec> {
    /// Nothing to publish: pre-Gloas, an external builder, or no contents were returned.
    Skip,
    /// Fetch the envelope from the beacon node by this block root.
    Fetch(Hash256),
    /// Sign and publish the envelope returned with the block.
    Local(Box<LocalPayloadContents<E>>),
}

impl<E: EthSpec> EnvelopeStep<E> {
    /// Split a Gloas produce response into the block and the envelope step it implies. Contents
    /// that were not requested are ignored, so the stateful path is unchanged.
    fn from_response(
        include_payload: bool,
        response: ProduceBlockV4Response<E>,
        slot: Slot,
    ) -> (BeaconBlock<E>, Self) {
        match (include_payload, response) {
            (
                true,
                ProduceBlockV4Response::BlockAndEnvelope(BlockAndEnvelope {
                    block,
                    execution_payload_envelope,
                    kzg_proofs,
                    blobs,
                }),
            ) => (
                block,
                Self::Local(Box::new(LocalPayloadContents {
                    envelope: execution_payload_envelope,
                    kzg_proofs,
                    blobs,
                })),
            ),
            (true, ProduceBlockV4Response::BlockOnly(block)) => {
                if block
                    .body()
                    .signed_execution_payload_bid()
                    .is_ok_and(|bid| bid.message.builder_index == BUILDER_INDEX_SELF_BUILD)
                {
                    // Inconsistent response: publish the block, the envelope cannot be signed.
                    warn!(
                        slot = slot.as_u64(),
                        "Beacon node omitted the payload contents for a self-built block, \
                         the execution payload envelope will not be published"
                    );
                }
                (block, Self::Skip)
            }
            (false, response) => {
                let block = response.into_block();
                let block_root = block.canonical_root();
                (block, Self::Fetch(block_root))
            }
        }
    }

    /// The `hash_tree_root` of the locally built payload, when there is one.
    fn local_payload_root(&self) -> Option<Hash256> {
        match self {
            Self::Local(contents) => Some(contents.envelope.payload.tree_hash_root()),
            Self::Fetch(_) | Self::Skip => None,
        }
    }
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
        local_payload_root: Option<Hash256>,
        builder_url: Option<String>,
    ) -> Result<(), BlockError> {
        let signing_timer = validator_metrics::start_timer(&validator_metrics::BLOCK_SIGNING_TIMES);

        let res = self
            .validator_store
            .sign_block(*validator_pubkey, unsigned_block, slot, local_payload_root)
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
        let builder_url_ref = builder_url.as_deref();
        proposer_fallback
            .request_proposers_first(|beacon_node| async {
                self.publish_signed_block_contents(&signed_block, beacon_node, builder_url_ref)
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

        let (block_proposer, unsigned_block, builder_url, envelope_step) = if fork_name
            .gloas_enabled()
        {
            // Resolve the validator's builder config for this proposal, signing each builder's
            // request auth via the cache. Sent in the POST `produceBlockV4` body below (the same
            // body is reused on the SSZ-to-JSON fallback and on every proposer-fallback BN). With
            // no builders configured this resolves to an empty list, so the proposal still falls
            // back to a local or p2p payload. Per-builder sign failures are logged and omitted
            // inside `builder_config`, so this never fails the proposal.
            let builder_config = self_ref
                .configured_builders
                .builder_config(|auth_data| {
                    self_ref.request_auth_cache.get_or_sign(
                        slot,
                        validator_pubkey,
                        auth_data,
                        |request_auth_v1| {
                            self_ref
                                .validator_store
                                .sign_request_auth_v1(validator_pubkey, request_auth_v1)
                        },
                    )
                })
                .await;
            debug!(
                slot = slot.as_u64(),
                builders = builder_config.builders.len(),
                "Resolved builder config for block production"
            );
            let builder_config_ref = &builder_config;
            let include_payload = self_ref.stateless_block_production;

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
                        .post_validator_blocks_v4_ssz::<S::E>(
                            slot,
                            randao_reveal_ref,
                            graffiti.as_ref(),
                            include_payload,
                            builder_config_ref,
                            self_ref.graffiti_policy,
                            fork_name,
                        )
                        .await
                })
                .await;

            // `builder_url` is the `Eth-Builder-Url` from the winning beacon node — echoed on publish
            // so it forwards the block to the builder that won selection.
            let (block_response, builder_url) = match ssz_block_response {
                Ok((ssz_block_response, metadata)) => (ssz_block_response, metadata.builder_url),
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
                            let (json_block_response, metadata) = beacon_node
                                .post_validator_blocks_v4::<S::E>(
                                    slot,
                                    randao_reveal_ref,
                                    graffiti.as_ref(),
                                    include_payload,
                                    builder_config_ref,
                                    self_ref.graffiti_policy,
                                    fork_name,
                                )
                                .await
                                .map_err(|e| {
                                    BlockError::Recoverable(format!(
                                        "Error from beacon node when producing block: {:?}",
                                        e
                                    ))
                                })?;

                            Ok((json_block_response, metadata.builder_url))
                        })
                        .await
                        .map_err(BlockError::from)?
                }
            };

            let (block_response, envelope_step) =
                EnvelopeStep::from_response(include_payload, block_response, slot);

            // Gloas blocks don't have blobs (they're in the execution layer)
            let block_contents = eth2::types::FullBlockContents::Block(block_response);
            (
                block_contents.block().proposer_index(),
                UnsignedBlock::Full(block_contents),
                builder_url,
                envelope_step,
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

            // Pre-Gloas has no builder-URL provenance (the V3 mev-boost path handles builder
            // forwarding itself), so there's nothing to echo on publish.
            match block_response {
                eth2::types::ProduceBlockV3Response::Full(block) => (
                    block.block().proposer_index(),
                    UnsignedBlock::Full(block),
                    None,
                    EnvelopeStep::Skip,
                ),
                eth2::types::ProduceBlockV3Response::Blinded(block) => (
                    block.proposer_index(),
                    UnsignedBlock::Blinded(block),
                    None,
                    EnvelopeStep::Skip,
                ),
            }
        };

        info!(slot = slot.as_u64(), "Received unsigned block");
        if proposer_index != Some(block_proposer) {
            return Err(BlockError::Recoverable(
                "Proposer index does not match block proposer. Beacon chain re-orged".to_string(),
            ));
        }

        let local_payload_root = envelope_step.local_payload_root();

        self_ref
            .sign_and_publish_block(
                &proposer_fallback,
                slot,
                graffiti,
                &validator_pubkey,
                unsigned_block,
                local_payload_root,
                builder_url,
            )
            .await?;

        match envelope_step {
            EnvelopeStep::Skip => {}
            // TODO(gloas): only fetch when the bid is self-build (#9948).
            EnvelopeStep::Fetch(beacon_block_root) => {
                self_ref
                    .fetch_sign_and_publish_payload_envelope(
                        &proposer_fallback,
                        slot,
                        beacon_block_root,
                        &validator_pubkey,
                    )
                    .await?;
            }
            EnvelopeStep::Local(contents) => {
                self_ref
                    .sign_and_publish_local_payload_envelope(
                        &proposer_fallback,
                        slot,
                        fork_name,
                        *contents,
                        &validator_pubkey,
                    )
                    .await?;
            }
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

    /// Sign the envelope returned with a self-built block and publish it with its blobs and KZG
    /// proofs via the same nodes as the block, since any beacon node can accept that form.
    #[instrument(skip_all)]
    async fn sign_and_publish_local_payload_envelope(
        &self,
        proposer_fallback: &ProposerFallback<T>,
        slot: Slot,
        fork_name: ForkName,
        contents: LocalPayloadContents<S::E>,
        validator_pubkey: &PublicKeyBytes,
    ) -> Result<(), BlockError> {
        let LocalPayloadContents {
            envelope,
            kzg_proofs,
            blobs,
        } = contents;
        let beacon_block_root = envelope.beacon_block_root;
        info!(
            slot = slot.as_u64(),
            %beacon_block_root,
            "Signing locally built execution payload envelope"
        );

        let signed_execution_payload_envelope = self
            .validator_store
            .sign_execution_payload_envelope(*validator_pubkey, envelope)
            .await
            .map_err(|e| {
                BlockError::Recoverable(format!(
                    "Error signing execution payload envelope: {:?}",
                    e
                ))
            })?;
        let signed_contents = SignedExecutionPayloadEnvelopeContents {
            signed_execution_payload_envelope,
            kzg_proofs,
            blobs,
        };
        let signed_contents = &signed_contents;

        proposer_fallback
            .request_proposers_first(|beacon_node| async move {
                beacon_node
                    .post_beacon_execution_payload_envelope_contents_ssz(
                        signed_contents,
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
            })
            .await?;

        info!(
            slot = slot.as_u64(),
            %beacon_block_root,
            "Successfully published signed execution payload envelope"
        );

        Ok(())
    }

    #[instrument(skip_all)]
    async fn publish_signed_block_contents(
        &self,
        signed_block: &SignedBlock<S::E>,
        beacon_node: BeaconNodeHttpClient,
        builder_url: Option<&str>,
    ) -> Result<(), BlockError> {
        match signed_block {
            SignedBlock::Full(signed_block) => {
                let _post_timer = validator_metrics::start_timer_vec(
                    &validator_metrics::BLOCK_SERVICE_TIMES,
                    &[validator_metrics::BEACON_BLOCK_HTTP_POST],
                );
                beacon_node
                    .post_beacon_blocks_v2_ssz(signed_block, None, builder_url)
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
    use beacon_node_fallback::{CandidateBeaconNode, Config as BeaconNodeConfig};
    use slot_clock::ManualSlotClock;
    use std::time::Duration;
    use types::{Blob, KzgProof, MainnetEthSpec};
    use validator_test_rig::mock_beacon_node::MockBeaconNode;
    use validator_test_rig::recording_validator_store::RecordingValidatorStore;
    use validator_test_rig::validator_client_harness::{S, ValidatorClientHarness};

    type Store = RecordingValidatorStore<S>;

    struct TestHarness {
        harness: ValidatorClientHarness,
        service: BlockService<Store, ManualSlotClock>,
    }

    impl TestHarness {
        async fn new_with_validators(num_validators: usize) -> Self {
            Self::new(num_validators, false, None).await
        }

        async fn new_stateless() -> Self {
            Self::new(1, true, None).await
        }

        /// A stateless-mode service that publishes to the returned proposer node first.
        async fn new_stateless_with_proposer_node() -> (Self, MockBeaconNode<MainnetEthSpec>) {
            let proposer_node = MockBeaconNode::<MainnetEthSpec>::new().await;
            let harness = Self::new(1, true, Some(&proposer_node)).await;
            (harness, proposer_node)
        }

        async fn new(
            num_validators: usize,
            stateless_block_production: bool,
            proposer_node: Option<&MockBeaconNode<MainnetEthSpec>>,
        ) -> Self {
            let harness = ValidatorClientHarness::new(num_validators).await;

            // advance the time to Slot 1
            harness
                .slot_clock
                .advance_time(harness.spec.get_slot_duration());

            let mut builder = BlockServiceBuilder::new()
                .validator_store(Arc::new(RecordingValidatorStore::new(
                    harness.validator_store.clone(),
                )))
                .slot_clock(harness.slot_clock.clone())
                .beacon_nodes(harness.beacon_nodes.clone())
                .executor(harness.test_runtime.task_executor.clone())
                .chain_spec(harness.spec.clone())
                .request_auth_cache(RequestAuthCache::default())
                .configured_builders(
                    BuilderStore::open_or_create(harness._validator_dir.path()).unwrap(),
                )
                .stateless_block_production(stateless_block_production);

            if let Some(proposer_node) = proposer_node {
                let candidate =
                    CandidateBeaconNode::new(proposer_node.beacon_api_client.clone(), 0);
                builder = builder.proposer_nodes(Arc::new(BeaconNodeFallback::new(
                    vec![candidate],
                    BeaconNodeConfig::default(),
                    vec![],
                    harness.spec.clone(),
                )));
            }

            Self {
                harness,
                service: builder.build().unwrap(),
            }
        }

        fn bn1(&mut self) -> &mut MockBeaconNode<MainnetEthSpec> {
            &mut self.harness.mock_beacon_node_1
        }

        fn bn2(&mut self) -> &mut MockBeaconNode<MainnetEthSpec> {
            &mut self.harness.mock_beacon_node_2
        }

        /// Propose at `slot` for the first validator and require success.
        async fn publish(&self, slot: Slot) {
            let result = self
                .service
                .clone()
                .get_validator_block_and_publish_block(slot, self.harness.pubkeys[0], None)
                .await;
            assert!(
                result.is_ok(),
                "Block production failed: {:?}",
                result.err()
            );
        }

        /// Assert `sign_block` was called once, for `block`, with `local_payload_root`.
        fn assert_signed_once(
            &self,
            block: &BeaconBlock<MainnetEthSpec>,
            local_payload_root: Option<Hash256>,
        ) {
            let calls = self.service.validator_store.sign_block_calls();
            assert_eq!(calls.len(), 1, "expected exactly one sign_block call");
            assert_eq!(calls[0].validator_pubkey, self.harness.pubkeys[0]);
            assert_eq!(calls[0].block_root, block.canonical_root());
            assert_eq!(calls[0].local_payload_root, local_payload_root);
        }
    }

    fn block_only(block: &BeaconBlock<MainnetEthSpec>) -> ProduceBlockV4Response<MainnetEthSpec> {
        ProduceBlockV4Response::BlockOnly(block.clone())
    }

    /// A Gloas block with a self-built bid.
    fn self_build_block(spec: &ChainSpec) -> BeaconBlock<MainnetEthSpec> {
        let mut block = BeaconBlock::empty(spec);
        let BeaconBlock::Gloas(gloas_block) = &mut block else {
            panic!("expected Gloas block");
        };
        gloas_block
            .body
            .signed_execution_payload_bid
            .message
            .builder_index = BUILDER_INDEX_SELF_BUILD;
        block
    }

    /// The `include_payload=true` response for a self-built `block`, with one blob and one proof.
    fn local_contents(block: &BeaconBlock<MainnetEthSpec>) -> BlockAndEnvelope<MainnetEthSpec> {
        let mut envelope = ExecutionPayloadEnvelope::empty();
        envelope.payload.slot_number = block.slot();
        envelope.payload.block_number = 7;
        envelope.builder_index = BUILDER_INDEX_SELF_BUILD;
        envelope.beacon_block_root = block.canonical_root();
        envelope.parent_beacon_block_root = block.parent_root();
        BlockAndEnvelope {
            block: block.clone(),
            execution_payload_envelope: envelope,
            kzg_proofs: KzgProofs::<MainnetEthSpec>::try_from(vec![KzgProof::empty()]).unwrap(),
            blobs: BlobsList::<MainnetEthSpec>::try_from(vec![Blob::<MainnetEthSpec>::default()])
                .unwrap(),
        }
    }

    /// Assert `node` received exactly one envelope publish matching `contents`.
    fn assert_published_contents(
        node: &MockBeaconNode<MainnetEthSpec>,
        contents: &BlockAndEnvelope<MainnetEthSpec>,
    ) {
        let received = node.execution_payload_envelope_contents.lock().unwrap();
        assert_eq!(received.len(), 1, "Expected one envelope contents publish");
        assert_eq!(
            received[0].signed_execution_payload_envelope.message,
            contents.execution_payload_envelope
        );
        assert_eq!(received[0].kzg_proofs, contents.kzg_proofs);
        assert_eq!(received[0].blobs, contents.blobs);
    }

    /// In stateless mode a `BlockOnly` response publishes the block alone with no payload root.
    async fn assert_stateless_block_only(
        make_block: impl FnOnce(&ChainSpec) -> BeaconBlock<MainnetEthSpec>,
    ) {
        let mut test_harness = TestHarness::new_stateless().await;
        let slot = Slot::new(1);
        let block = make_block(&test_harness.harness.spec);

        test_harness.bn1().mock_post_validator_blocks_v4_ssz(
            &block_only(&block),
            true,
            ForkName::Gloas,
            slot,
        );
        let mock_post_block = test_harness
            .bn1()
            .mock_post_beacon_blocks_v2_ssz(ForkName::Gloas);
        let mock_get_envelope = test_harness
            .bn1()
            .mock_get_validator_execution_payload_envelope_ssz(
                &ExecutionPayloadEnvelope::empty(),
                slot,
                block.canonical_root(),
            );
        let mock_post_bare_envelope = test_harness
            .bn1()
            .mock_post_beacon_execution_payload_envelope_ssz();
        let mock_post_contents = test_harness
            .bn1()
            .mock_post_beacon_execution_payload_envelope_contents_ssz();

        test_harness.publish(slot).await;

        mock_post_block.expect(1).assert();
        mock_get_envelope.expect(0).assert();
        mock_post_bare_envelope.expect(0).assert();
        mock_post_contents.expect(0).assert();
        test_harness.assert_signed_once(&block, None);
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
            .mock_post_validator_blocks_v4_ssz(
                &block_only(&block),
                false,
                ForkName::Gloas,
                different_notification_slot,
            );

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
            .mock_post_validator_blocks_v4_ssz(
                &block_only(&block),
                false,
                ForkName::Gloas,
                same_notification_slot,
            );

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
        let block = BeaconBlock::empty(&test_harness.harness.spec);
        let envelope = ExecutionPayloadEnvelope::empty();

        test_harness
            .harness
            .mock_beacon_node_1
            .mock_post_validator_blocks_v4_ssz(&block_only(&block), false, ForkName::Gloas, slot);
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

        test_harness.publish(slot).await;

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

        test_harness.assert_signed_once(&block, None);
    }

    #[tokio::test]
    async fn stateless_self_build_publishes_inline_envelope_contents_through_proposer_node() {
        let (mut test_harness, mut proposer_node) =
            TestHarness::new_stateless_with_proposer_node().await;

        let slot = Slot::new(1);
        let block = self_build_block(&test_harness.harness.spec);
        let contents = local_contents(&block);
        let expected_payload_root = contents.execution_payload_envelope.payload.tree_hash_root();

        // Production goes to a beacon node; the block and envelope must go to the proposer node.
        test_harness.bn1().mock_post_validator_blocks_v4_ssz(
            &ProduceBlockV4Response::BlockAndEnvelope(contents.clone()),
            true,
            ForkName::Gloas,
            slot,
        );
        let mock_get_envelope = test_harness
            .bn1()
            .mock_get_validator_execution_payload_envelope_ssz(
                &contents.execution_payload_envelope,
                slot,
                block.canonical_root(),
            );
        let mock_beacon_node_post_contents = test_harness
            .bn1()
            .mock_post_beacon_execution_payload_envelope_contents_ssz();
        let mock_post_block = proposer_node.mock_post_beacon_blocks_v2_ssz(ForkName::Gloas);
        let mock_post_bare_envelope =
            proposer_node.mock_post_beacon_execution_payload_envelope_ssz();
        let mock_post_contents =
            proposer_node.mock_post_beacon_execution_payload_envelope_contents_ssz();

        test_harness.publish(slot).await;

        mock_post_block.expect(1).assert();
        mock_post_contents.expect(1).assert();
        mock_post_bare_envelope.expect(0).assert();
        mock_get_envelope.expect(0).assert();
        mock_beacon_node_post_contents.expect(0).assert();

        test_harness.assert_signed_once(&block, Some(expected_payload_root));
        assert_published_contents(&proposer_node, &contents);
        assert_eq!(
            proposer_node.received_full_blocks.lock().unwrap().len(),
            1,
            "Expected one published block"
        );
    }

    #[tokio::test]
    async fn stateless_ssz_produce_fails_and_json_succeeds_with_inline_contents() {
        let mut test_harness = TestHarness::new_stateless().await;

        let slot = Slot::new(1);
        let block = self_build_block(&test_harness.harness.spec);
        let contents = local_contents(&block);
        let expected_payload_root = contents.execution_payload_envelope.payload.tree_hash_root();

        let mock_ssz_1 = test_harness
            .bn1()
            .mock_post_validator_blocks_v4_ssz_error(slot, true);
        let mock_ssz_2 = test_harness
            .bn2()
            .mock_post_validator_blocks_v4_ssz_error(slot, true);
        let mock_json = test_harness.bn1().mock_post_validator_blocks_v4(
            &ProduceBlockV4Response::BlockAndEnvelope(contents.clone()),
            true,
            ForkName::Gloas,
            slot,
        );
        let mock_post_block = test_harness
            .bn1()
            .mock_post_beacon_blocks_v2_ssz(ForkName::Gloas);
        let mock_get_envelope = test_harness
            .bn1()
            .mock_get_validator_execution_payload_envelope_ssz(
                &contents.execution_payload_envelope,
                slot,
                block.canonical_root(),
            );
        let mock_post_contents = test_harness
            .bn1()
            .mock_post_beacon_execution_payload_envelope_contents_ssz();

        test_harness.publish(slot).await;

        // `first_success` makes two passes over the candidates before the JSON fallback.
        mock_ssz_1.expect(2).assert();
        mock_ssz_2.expect(2).assert();
        mock_json.expect(1).assert();
        mock_post_block.expect(1).assert();
        mock_post_contents.expect(1).assert();
        mock_get_envelope.expect(0).assert();

        test_harness.assert_signed_once(&block, Some(expected_payload_root));
        assert_published_contents(&test_harness.harness.mock_beacon_node_1, &contents);
    }

    #[tokio::test]
    async fn flag_off_ignores_unsolicited_inline_contents() {
        let mut test_harness = TestHarness::new_with_validators(1).await;

        let slot = Slot::new(1);
        let block = self_build_block(&test_harness.harness.spec);
        let contents = local_contents(&block);

        // The beacon node attaches contents although `include_payload=false` was requested.
        test_harness.bn1().mock_post_validator_blocks_v4_ssz(
            &ProduceBlockV4Response::BlockAndEnvelope(contents.clone()),
            false,
            ForkName::Gloas,
            slot,
        );
        let mock_post_block = test_harness
            .bn1()
            .mock_post_beacon_blocks_v2_ssz(ForkName::Gloas);
        let mock_get_envelope = test_harness
            .bn1()
            .mock_get_validator_execution_payload_envelope_ssz(
                &contents.execution_payload_envelope,
                slot,
                block.canonical_root(),
            );
        let mock_post_bare_envelope = test_harness
            .bn1()
            .mock_post_beacon_execution_payload_envelope_ssz();
        let mock_post_contents = test_harness
            .bn1()
            .mock_post_beacon_execution_payload_envelope_contents_ssz();

        test_harness.publish(slot).await;

        // The stateful path runs as if the contents had not been returned.
        mock_post_block.expect(1).assert();
        mock_get_envelope.expect(1).assert();
        mock_post_bare_envelope.expect(1).assert();
        mock_post_contents.expect(0).assert();
        test_harness.assert_signed_once(&block, None);
    }

    #[tokio::test]
    async fn stateless_envelope_falls_back_from_proposer_node_to_beacon_node() {
        let (mut test_harness, mut proposer_node) =
            TestHarness::new_stateless_with_proposer_node().await;

        let slot = Slot::new(1);
        let block = self_build_block(&test_harness.harness.spec);
        let contents = local_contents(&block);

        test_harness.bn1().mock_post_validator_blocks_v4_ssz(
            &ProduceBlockV4Response::BlockAndEnvelope(contents.clone()),
            true,
            ForkName::Gloas,
            slot,
        );
        let mock_beacon_node_post_contents = test_harness
            .bn1()
            .mock_post_beacon_execution_payload_envelope_contents_ssz();
        let mock_post_block = proposer_node.mock_post_beacon_blocks_v2_ssz(ForkName::Gloas);
        let mock_proposer_post_contents =
            proposer_node.mock_post_beacon_execution_payload_envelope_contents_ssz_error();

        test_harness.publish(slot).await;

        // The proposer node accepted the block but rejects the envelope, so the beacon nodes are
        // tried next with the same contents.
        mock_post_block.expect(1).assert();
        mock_proposer_post_contents.expect(2).assert();
        mock_beacon_node_post_contents.expect(1).assert();
        assert_published_contents(&test_harness.harness.mock_beacon_node_1, &contents);
    }

    #[tokio::test]
    async fn stateless_external_builder_bid_publishes_block_only() {
        assert_stateless_block_only(BeaconBlock::empty).await;
    }

    #[tokio::test]
    async fn stateless_self_build_without_inline_contents_publishes_block_only() {
        assert_stateless_block_only(self_build_block).await;
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
            .mock_post_validator_blocks_v4_ssz_error(slot, false);
        let mock_bn_2 = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_validator_blocks_v4_ssz_error(slot, false);

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
            .mock_post_validator_blocks_v4_ssz_error(slot, false);
        let mock_json = test_harness
            .harness
            .mock_beacon_node_2
            .mock_post_validator_blocks_v4(&block_only(&block), false, ForkName::Gloas, slot);

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
