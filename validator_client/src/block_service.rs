use crate::beacon_node_fallback::{Error as FallbackError, Errors};
use crate::{
    beacon_node_fallback::{BeaconNodeFallback, RequireSynced},
    graffiti_file::GraffitiFile,
    OfflineOnFailure,
};
use crate::{http_metrics::metrics, validator_store::ValidatorStore};
use environment::RuntimeContext;
use eth2::types::{Graffiti, VariableList};
use slog::{crit, debug, error, info, trace, warn};
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{
    BlindedPayload, BlobsSidecar, BlockType, EthSpec, ExecPayload, ForkName, FullPayload,
    PublicKeyBytes, Slot,
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
    context: Option<RuntimeContext<E>>,
    graffiti: Option<Graffiti>,
    graffiti_file: Option<GraffitiFile>,
}

impl<T: SlotClock + 'static, E: EthSpec> BlockServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            validator_store: None,
            slot_clock: None,
            beacon_nodes: None,
            context: None,
            graffiti: None,
            graffiti_file: None,
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
                graffiti: self.graffiti,
                graffiti_file: self.graffiti_file,
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    validator_store: Arc<ValidatorStore<T, E>>,
    slot_clock: Arc<T>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    context: RuntimeContext<E>,
    graffiti: Option<Graffiti>,
    graffiti_file: Option<GraffitiFile>,
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
                    let publish_result = if builder_proposals {
                        let mut result = service.clone()
                            .publish_block::<BlindedPayload<E>>(slot, validator_pubkey)
                            .await;
                        match result.as_ref() {
                            Err(BlockError::Recoverable(e)) => {
                                error!(log, "Error whilst producing a blinded block, attempting to \
                                    publish full block"; "error" => ?e);
                                result = service
                                    .publish_block::<FullPayload<E>>(slot, validator_pubkey)
                                    .await;
                            },
                            Err(BlockError::Irrecoverable(e))  => {
                                error!(log, "Error whilst producing a blinded block, cannot fallback \
                                    because the block was signed"; "error" => ?e);
                            },
                            _ => {},
                        };
                        result
                    } else {
                        service
                            .publish_block::<FullPayload<E>>(slot, validator_pubkey)
                            .await
                    };
                    if let Err(e) = publish_result {
                        crit!(
                            log,
                            "Error whilst producing block";
                            "message" => ?e
                        );
                    }
                },
                "block service",
            );
        }

        Ok(())
    }

    /// Produce a block at the given slot for validator_pubkey
    async fn publish_block<Payload: ExecPayload<E>>(
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

        let randao_reveal = self
            .validator_store
            .randao_reveal(validator_pubkey, slot.epoch(E::slots_per_epoch()))
            .await
            .map_err(|e| {
                BlockError::Recoverable(format!(
                    "Unable to produce randao reveal signature: {:?}",
                    e
                ))
            })?
            .into();

        let graffiti = self
            .graffiti_file
            .clone()
            .and_then(|mut g| match g.load_graffiti(&validator_pubkey) {
                Ok(g) => g,
                Err(e) => {
                    warn!(log, "Failed to read graffiti file"; "error" => ?e);
                    None
                }
            })
            .or_else(|| self.validator_store.graffiti(&validator_pubkey))
            .or(self.graffiti);

        let randao_reveal_ref = &randao_reveal;
        let self_ref = &self;
        let proposer_index = self.validator_store.validator_index(&validator_pubkey);
        let validator_pubkey_ref = &validator_pubkey;

        match self.context.eth2_config.spec.fork_name_at_slot::<E>(slot) {
            ForkName::Base | ForkName::Altair | ForkName::Merge => {
                // Request block from first responsive beacon node.
                let block = self
                    .beacon_nodes
                    .first_success(
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

                let signed_block = self_ref
                    .validator_store
                    .sign_block::<Payload>(*validator_pubkey_ref, block, current_slot)
                    .await
                    .map_err(|e| {
                        BlockError::Recoverable(format!("Unable to sign block: {:?}", e))
                    })?;

                // Publish block with first available beacon node.
                self.beacon_nodes
                    .first_success(
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
            }
            ForkName::Eip4844 => {
                if matches!(Payload::block_type(), BlockType::Blinded) {
                    //FIXME(sean)
                    crit!(
                        log,
                        "`--builder-payloads` not yet supported for EIP-4844 fork"
                    );
                    return Ok(());
                }

                // Request block from first responsive beacon node.
                let block_and_blobs = self
                    .beacon_nodes
                    .first_success(
                        RequireSynced::No,
                        OfflineOnFailure::Yes,
                        |beacon_node| async move {

                                    let _get_timer = metrics::start_timer_vec(
                                        &metrics::BLOCK_SERVICE_TIMES,
                                        &[metrics::BEACON_BLOCK_HTTP_GET],
                                    );
                            let block_and_blobs =         beacon_node
                                        .get_validator_blocks_and_blobs::<E, Payload>(
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
                                        .data;

                            if proposer_index != Some(block_and_blobs.block.proposer_index()) {
                                return Err(BlockError::Recoverable(
                                    "Proposer index does not match block proposer. Beacon chain re-orged"
                                        .to_string(),
                                ));
                            }

                            Ok::<_, BlockError>(block_and_blobs)
                        },
                    )
                    .await?;

                let blobs_sidecar = BlobsSidecar {
                    beacon_block_root: block_and_blobs.block.canonical_root(),
                    beacon_block_slot: block_and_blobs.block.slot(),
                    blobs: VariableList::from(block_and_blobs.blobs),
                    kzg_aggregate_proof: block_and_blobs.kzg_aggregate_proof,
                };

                let block = block_and_blobs.block;
                let block_publish_future = async {
                    let signed_block = self_ref
                        .validator_store
                        .sign_block::<Payload>(*validator_pubkey_ref, block, current_slot)
                        .await
                        .map_err(|e| {
                            BlockError::Recoverable(format!("Unable to sign block: {:?}", e))
                        })?;

                    // Publish block with first available beacon node.
                    self.beacon_nodes
                        .first_success(
                            RequireSynced::No,
                            OfflineOnFailure::Yes,
                            |beacon_node| async {
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
                                    })?;
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

                    Ok::<_, BlockError>(())
                };

                let blob_publish_future = async {
                    let signed_blobs = self_ref
                        .validator_store
                        .sign_blobs(*validator_pubkey_ref, blobs_sidecar, current_slot)
                        .await
                        .map_err(|e| {
                            BlockError::Recoverable(format!("Unable to sign blob: {:?}", e))
                        })?;

                    // Publish block with first available beacon node.
                    self.beacon_nodes
                        .first_success(
                            RequireSynced::No,
                            OfflineOnFailure::Yes,
                            |beacon_node| async {
                                let _post_timer = metrics::start_timer_vec(
                                    &metrics::BLOCK_SERVICE_TIMES,
                                    &[metrics::BEACON_BLOB_HTTP_POST],
                                );
                                beacon_node.post_beacon_blobs(&signed_blobs).await.map_err(
                                    |e| {
                                        BlockError::Irrecoverable(format!(
                                            "Error from beacon node when publishing blob: {:?}",
                                            e
                                        ))
                                    },
                                )?;
                                Ok::<_, BlockError>(())
                            },
                        )
                        .await?;

                    info!(
                        log,
                        "Successfully published blobs";
                        "block_type" => ?Payload::block_type(),
                        "slot" => signed_blobs.message.beacon_block_slot.as_u64(),
                        "block_root" => ?signed_blobs.message.beacon_block_root,
                        "blobs_len" => signed_blobs.message.blobs.len(),
                    );

                    Ok::<_, BlockError>(())
                };

                let (res_block, res_blob) = tokio::join!(block_publish_future, blob_publish_future);

                res_block?;
                res_blob?;
            }
        }

        Ok(())
    }
}
