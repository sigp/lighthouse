use crate::execution_payload::validate_merge_block;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, BlockError, ExecutionPayloadError};
use proto_array::InvalidationOperation;
use slog::{crit, debug, error, info, warn};
use slot_clock::SlotClock;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::per_block_processing::is_merge_transition_complete;
use std::sync::Arc;
use store::{DBColumn, Error as StoreError, HotColdDB, KeyValueStore, StoreItem};
use task_executor::{ShutdownReason, TaskExecutor};
use tokio::time::sleep;
use tree_hash::TreeHash;
use types::{BeaconBlockRef, EthSpec, Hash256, Slot};
use DBColumn::OptimisticTransitionBlock as OTBColumn;

#[derive(Clone, Debug, Decode, Encode)]
pub struct OptimisticTransitionBlock {
    root: Hash256,
    slot: Slot,
}

impl OptimisticTransitionBlock {
    // types::BeaconBlockRef<'_, <T as BeaconChainTypes>::EthSpec>
    pub fn from_block<T: BeaconChainTypes>(block: BeaconBlockRef<T::EthSpec>) -> Self {
        Self {
            root: block.tree_hash_root(),
            slot: block.slot(),
        }
    }

    pub fn root(&self) -> &Hash256 {
        &self.root
    }

    pub fn slot(&self) -> &Slot {
        &self.slot
    }

    pub fn persist_in_store<T, A>(&self, store: A) -> Result<(), StoreError>
    where
        T: BeaconChainTypes,
        A: AsRef<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    {
        if store
            .as_ref()
            .item_exists::<OptimisticTransitionBlock>(&self.root)?
        {
            return Ok(());
        } else {
            store.as_ref().put_item(&self.root, self)
        }
    }

    pub fn remove_from_store<T, A>(&self, store: A) -> Result<(), StoreError>
    where
        T: BeaconChainTypes,
        A: AsRef<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
    {
        store
            .as_ref()
            .hot_db
            .key_delete(OTBColumn.into(), self.root.as_bytes())
    }

    fn is_canonical<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<bool, BeaconChainError> {
        Ok(chain
            .forwards_iter_block_roots_until(self.slot, self.slot)?
            .next()
            .transpose()?
            .map(|(root, _)| root)
            == Some(self.root))
    }
}

impl StoreItem for OptimisticTransitionBlock {
    fn db_column() -> DBColumn {
        OTBColumn
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

/// At 12s slot times, the means that the payload preparation routine will run 4s before the start
/// of each slot (`12 / 3 = 4`).
pub const EPOCH_DELAY_FACTOR: u32 = 4;

/// Spawns a routine which checks the validity of any optimistically imported transition blocks
///
/// This routine will run once per epoch, at `epoch_duration / EPOCH_DELAY_FACTOR` after
/// the start of each epoch.
///
/// The service will not be started if there is no `execution_layer` on the `chain`.
pub fn start_otb_verification_service<T: BeaconChainTypes>(
    executor: TaskExecutor,
    chain: Arc<BeaconChain<T>>,
) {
    // Avoid spawning the service if there's no EL, it'll just error anyway.
    if chain.execution_layer.is_some() {
        executor.clone().spawn(
            async move { otb_verification_service(chain).await },
            "otb_verification_service",
        );
    }
}

fn load_optimistic_transition_blocks<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> Result<Vec<OptimisticTransitionBlock>, StoreError> {
    chain
        .store
        .hot_db
        .iter_column(OTBColumn)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|(_, bytes)| OptimisticTransitionBlock::from_store_bytes(&bytes))
        .collect()
}

/// Loop indefinitely, calling `BeaconChain::prepare_beacon_proposer_async` at an interval.
async fn otb_verification_service<T: BeaconChainTypes>(chain: Arc<BeaconChain<T>>) {
    let epoch_duration = chain.slot_clock.slot_duration() * T::EthSpec::slots_per_epoch() as u32;

    loop {
        match chain
            .slot_clock
            .duration_to_next_epoch(T::EthSpec::slots_per_epoch())
        {
            Some(duration) => {
                let additional_delay = epoch_duration / EPOCH_DELAY_FACTOR;
                sleep(duration + additional_delay).await;

                debug!(
                    chain.log,
                    "OTB Verification Service Firing";
                );

                if !is_merge_transition_complete(
                    &chain.canonical_head.cached_head().snapshot.beacon_state,
                ) {
                    // We are pre-merge. Nothing to do yet.
                    continue;
                }

                let finalized_slot = match chain
                    .canonical_head
                    .fork_choice_read_lock()
                    .get_finalized_block()
                {
                    Ok(block) => block.slot,
                    Err(e) => {
                        warn!(chain.log, "Error Retrieving Finalized Slot: {:?}", e);
                        continue;
                    }
                };

                // load all optimistically imported transition blocks from the database
                // and separate them into non-canonical, finalized canonical, and
                // unfinalized canonical
                let mut non_canonical_otbs = vec![];
                let (finalized_canonical_otbs, unfinalized_canonical_otbs) =
                    match load_optimistic_transition_blocks(chain.as_ref()) {
                        Ok(blocks) => {
                            if blocks.is_empty() {
                                // there are no optimistic blocks in the database, we can exit
                                // the service since the merge transition is completed
                                break;
                            }

                            blocks
                                .into_iter()
                                .filter_map(|otb| match otb.is_canonical(chain.as_ref()) {
                                    Ok(true) => Some(otb),
                                    Ok(false) => {
                                        non_canonical_otbs.push(otb);
                                        None
                                    }
                                    Err(e) => {
                                        warn!(
                                            chain.log,
                                            "Error Iterating Over Canonical Blocks: {:?}", e
                                        );
                                        None
                                    }
                                })
                                .partition::<Vec<_>, _>(|otb| *otb.slot() <= finalized_slot)
                        }
                        Err(e) => {
                            warn!(
                                chain.log,
                                "Error Loading Optimistic Transition Blocks: {:?}", e
                            );
                            continue;
                        }
                    };

                // remove non-canonical blocks that conflict with finalized checkpoint from the database
                for otb in non_canonical_otbs {
                    if *otb.slot() <= finalized_slot {
                        if let Err(e) = otb.remove_from_store::<T, _>(&chain.store) {
                            warn!(
                                chain.log,
                                "Error Removing Optimistic Transition Block from Database: {:?}", e
                            );
                        }
                    }
                }

                // ensure finalized canonical otb are valid, otherwise kill client
                for otb in finalized_canonical_otbs {
                    match chain.store.get_full_block(otb.root()) {
                        Ok(Some(block)) => {
                            match validate_merge_block(&chain, block.message()).await {
                                Ok(()) => {
                                    // merge transition block is valid, remove it from OTB
                                    if let Err(e) = otb.remove_from_store::<T, _>(&chain.store) {
                                        warn!(chain.log, "Error Removing Optimistic Transition Block from Database: {:?}", e);
                                    } else {
                                        info!(chain.log, "Validated Merge Transition Block");
                                    }
                                }
                                Err(BlockError::ExecutionPayloadError(
                                    ExecutionPayloadError::InvalidTerminalPoWBlock { .. },
                                )) => {
                                    // Finalized Merge Transition Block is Invalid! Kill the Client!
                                    crit!(
                                        chain.log,
                                        "Finalized Merge Transition Block is Invalid!";
                                        "msg" => "You must use the `--purge-db` flag to clear the database and restart sync. \
                                        You may be on a hostile network.",
                                        "block_hash" => ?block.canonical_root()
                                    );
                                    let mut shutdown_sender = chain.shutdown_sender();
                                    if let Err(e) =
                                        shutdown_sender.try_send(ShutdownReason::Failure(
                                            "Finalized Merge Transition Block is Invalid",
                                        ))
                                    {
                                        crit!(chain.log, "Failed to shut down client: {:?}", e);
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                        Ok(None) => warn!(
                            chain.log,
                            "No Block Found for Finalized Optimistic Transition Block: {:?}", otb
                        ),
                        Err(e) => {
                            warn!(chain.log, "Error Loading Full Block from Database: {:?}", e)
                        }
                    }
                }

                // attempt to validate any non-finalized canonical otb blocks
                for otb in unfinalized_canonical_otbs {
                    match chain.store.get_full_block(otb.root()) {
                        Ok(Some(block)) => {
                            match validate_merge_block(&chain, block.message()).await {
                                Ok(()) => {
                                    // merge transition block is valid, remove it from OTB
                                    if let Err(e) = otb.remove_from_store::<T, _>(&chain.store) {
                                        warn!(chain.log, "Error Removing Optimistic Transition Block from Database: {:?}", e);
                                    } else {
                                        info!(chain.log, "Validated Merge Transition Block");
                                    }
                                }
                                Err(BlockError::ExecutionPayloadError(
                                    ExecutionPayloadError::InvalidTerminalPoWBlock { .. },
                                )) => {
                                    // Unfinalized Merge Transition Block is Invalid -> Run process_invalid_execution_payload
                                    warn!(chain.log, "Merge Transition Block Invalid: {:?}", otb);
                                    if let Err(e) = chain
                                        .process_invalid_execution_payload(
                                            &InvalidationOperation::InvalidateOne {
                                                block_root: *otb.root(),
                                            },
                                        )
                                        .await
                                    {
                                        warn!(chain.log, "Error During process_invalid_execution_payload for Invalid Merge Transition Block: {:?}", e);
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                        Ok(None) => warn!(
                            chain.log,
                            "No Block Found for UnFinalized Optimistic Transition Block: {:?}", otb
                        ),
                        Err(e) => {
                            warn!(chain.log, "Error Loading Full Block from Database: {:?}", e)
                        }
                    }
                }

                continue;
            }
            None => {
                error!(chain.log, "Failed to read slot clock");
                // If we can't read the slot clock, just wait another epoch.
                sleep(epoch_duration).await;
                continue;
            }
        };
    }
    debug!(chain.log, "No Optimistic Transition Blocks in Database"; "msg" => "Shutting down OTB Verification Service");
}
