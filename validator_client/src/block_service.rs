use crate::validator_store::ValidatorStore;
use environment::RuntimeContext;
use eth2::{types::Graffiti, BeaconNodeHttpClient};
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
    beacon_node: Option<BeaconNodeHttpClient>,
    context: Option<RuntimeContext<E>>,
    graffiti: Option<Graffiti>,
}

impl<T: SlotClock + 'static, E: EthSpec> BlockServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            validator_store: None,
            slot_clock: None,
            beacon_node: None,
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

    pub fn beacon_node(mut self, beacon_node: BeaconNodeHttpClient) -> Self {
        self.beacon_node = Some(beacon_node);
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
                    .ok_or_else(|| "Cannot build BlockService without validator_store")?,
                slot_clock: self
                    .slot_clock
                    .ok_or_else(|| "Cannot build BlockService without slot_clock")?,
                beacon_node: self
                    .beacon_node
                    .ok_or_else(|| "Cannot build BlockService without beacon_node")?,
                context: self
                    .context
                    .ok_or_else(|| "Cannot build BlockService without runtime_context")?,
                graffiti: self.graffiti,
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    validator_store: ValidatorStore<T, E>,
    slot_clock: Arc<T>,
    beacon_node: BeaconNodeHttpClient,
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

        proposers.into_iter().for_each(|validator_pubkey| {
            let service = self.clone();
            let log = log.clone();
            self.inner.context.executor.runtime_handle().spawn(
                service
                    .publish_block(slot, validator_pubkey)
                    .map_err(move |e| {
                        crit!(
                            log,
                            "Error whilst producing block";
                            "message" => e
                        )
                    }),
            );
        });

        Ok(())
    }

    /// Produce a block at the given slot for validator_pubkey
    async fn publish_block(self, slot: Slot, validator_pubkey: PublicKey) -> Result<(), String> {
        let log = self.context.log();

        let current_slot = self
            .slot_clock
            .now()
            .ok_or_else(|| "Unable to determine current slot from clock".to_string())?;

        let randao_reveal = self
            .validator_store
            .randao_reveal(&validator_pubkey, slot.epoch(E::slots_per_epoch()))
            .ok_or_else(|| "Unable to produce randao reveal".to_string())?;

        let block = self
            .beacon_node
            .get_validator_blocks(slot, randao_reveal.into(), self.graffiti.as_ref())
            .await
            .map_err(|e| format!("Error from beacon node when producing block: {:?}", e))?
            .data;

        let signed_block = self
            .validator_store
            .sign_block(&validator_pubkey, block, current_slot)
            .ok_or_else(|| "Unable to sign block".to_string())?;

        self.beacon_node
            .post_beacon_blocks(&signed_block)
            .await
            .map_err(|e| format!("Error from beacon node when publishing block: {:?}", e))?;

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
