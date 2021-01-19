use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::{http_metrics::metrics, validator_store::ValidatorStore};
use environment::RuntimeContext;
use eth2::types::Graffiti;
use futures::channel::mpsc::Receiver;
use futures::{StreamExt, TryFutureExt};
use slog::{crit, debug, error, info, trace, warn};
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use types::{EthSpec, PublicKey, Slot};

/// Builds a `BlockService`.
pub struct BlockServiceBuilder<T, E: EthSpec> {
    validator_store: Option<ValidatorStore<T, E>>,
    slot_clock: Option<Arc<T>>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T, E>>>,
    context: Option<RuntimeContext<E>>,
    graffiti: Option<Graffiti>,
}

impl<T: SlotClock + 'static, E: EthSpec> BlockServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            validator_store: None,
            slot_clock: None,
            beacon_nodes: None,
            context: None,
            graffiti: None,
        }
    }

    pub fn validator_store(mut self, store: ValidatorStore<T, E>) -> Self {
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
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    validator_store: ValidatorStore<T, E>,
    slot_clock: Arc<T>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    context: RuntimeContext<E>,
    graffiti: Option<Graffiti>,
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
    pub block_proposers: Vec<PublicKey>,
}

impl<T: SlotClock + 'static, E: EthSpec> BlockService<T, E> {
    pub fn start_update_service(
        self,
        notification_rx: Receiver<BlockServiceNotification>,
    ) -> Result<(), String> {
        let log = self.context.log().clone();

        info!(log, "Block production service started");

        let executor = self.inner.context.executor.clone();

        let block_service_fut = notification_rx.for_each(move |notif| {
            let service = self.clone();
            async move {
                service.do_update(notif).await.ok();
            }
        });

        executor.spawn(block_service_fut, "block_service");

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
            let service = self.clone();
            let log = log.clone();
            self.inner.context.executor.spawn(
                service
                    .publish_block(slot, validator_pubkey)
                    .unwrap_or_else(move |e| {
                        crit!(
                            log,
                            "Error whilst producing block";
                            "message" => e
                        );
                    }),
                "block service",
            );
        }

        Ok(())
    }

    /// Produce a block at the given slot for validator_pubkey
    async fn publish_block(self, slot: Slot, validator_pubkey: PublicKey) -> Result<(), String> {
        let log = self.context.log();
        let _timer =
            metrics::start_timer_vec(&metrics::BLOCK_SERVICE_TIMES, &[metrics::BEACON_BLOCK]);

        let current_slot = self
            .slot_clock
            .now()
            .ok_or("Unable to determine current slot from clock")?;

        let randao_reveal = self
            .validator_store
            .randao_reveal(&validator_pubkey, slot.epoch(E::slots_per_epoch()))
            .ok_or("Unable to produce randao reveal")?
            .into();

        let randao_reveal_ref = &randao_reveal;
        let self_ref = &self;
        let validator_pubkey_ref = &validator_pubkey;
        let signed_block = self
            .beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                let block = beacon_node
                    .get_validator_blocks(slot, randao_reveal_ref, self_ref.graffiti.as_ref())
                    .await
                    .map_err(|e| format!("Error from beacon node when producing block: {:?}", e))?
                    .data;

                let signed_block = self_ref
                    .validator_store
                    .sign_block(validator_pubkey_ref, block, current_slot)
                    .ok_or("Unable to sign block")?;

                beacon_node
                    .post_beacon_blocks(&signed_block)
                    .await
                    .map_err(|e| {
                        format!("Error from beacon node when publishing block: {:?}", e)
                    })?;

                Ok::<_, String>(signed_block)
            })
            .await
            .map_err(|e| e.to_string())?;

        info!(
            log,
            "Successfully published block";
            "deposits" => signed_block.message.body.deposits.len(),
            "attestations" => signed_block.message.body.attestations.len(),
            "slot" => signed_block.slot().as_u64(),
        );

        Ok(())
    }
}
