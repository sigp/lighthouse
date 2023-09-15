use crate::execution_payload::{validate_merge_block, AllowOptimisticImport};
use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BlockError, ExecutionPayloadError,
    INVALID_FINALIZED_MERGE_TRANSITION_BLOCK_SHUTDOWN_REASON,
};
use itertools::process_results;
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

#[derive(Clone, Debug, Decode, Encode, PartialEq)]
pub struct OptimisticTransitionBlock {
    root: Hash256,
    slot: Slot,
}

impl OptimisticTransitionBlock {
    // types::BeaconBlockRef<'_, <T as BeaconChainTypes>::EthSpec>
    pub fn from_block<E: EthSpec>(block: BeaconBlockRef<E>) -> Self {
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
            Ok(())
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

/// The routine is expected to run once per epoch, 1/4th through the epoch.
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
        executor.spawn(
            async move { otb_verification_service(chain).await },
            "otb_verification_service",
        );
    }
}

pub fn load_optimistic_transition_blocks<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> Result<Vec<OptimisticTransitionBlock>, StoreError> {
    process_results(chain.store.hot_db.iter_column(OTBColumn), |iter| {
        iter.map(|(_, bytes)| OptimisticTransitionBlock::from_store_bytes(&bytes))
            .collect()
    })?
}

#[derive(Debug)]
pub enum Error {
    ForkChoice(String),
    BeaconChain(BeaconChainError),
    StoreError(StoreError),
    NoBlockFound(OptimisticTransitionBlock),
}

pub async fn validate_optimistic_transition_blocks<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    otbs: Vec<OptimisticTransitionBlock>,
) -> Result<(), Error> {
    let finalized_slot = chain
        .canonical_head
        .fork_choice_read_lock()
        .get_finalized_block()
        .map_err(|e| Error::ForkChoice(format!("{:?}", e)))?
        .slot;

    // separate otbs into
    //     non-canonical
    //     finalized canonical
    //     unfinalized canonical
    let mut non_canonical_otbs = vec![];
    let (finalized_canonical_otbs, unfinalized_canonical_otbs) = process_results(
        otbs.into_iter().map(|otb| {
            otb.is_canonical(chain)
                .map(|is_canonical| (otb, is_canonical))
        }),
        |pair_iter| {
            pair_iter
                .filter_map(|(otb, is_canonical)| {
                    if is_canonical {
                        Some(otb)
                    } else {
                        non_canonical_otbs.push(otb);
                        None
                    }
                })
                .partition::<Vec<_>, _>(|otb| *otb.slot() <= finalized_slot)
        },
    )
    .map_err(Error::BeaconChain)?;

    // remove non-canonical blocks that conflict with finalized checkpoint from the database
    for otb in non_canonical_otbs {
        if *otb.slot() <= finalized_slot {
            otb.remove_from_store::<T, _>(&chain.store)
                .map_err(Error::StoreError)?;
        }
    }

    // ensure finalized canonical otb are valid, otherwise kill client
    for otb in finalized_canonical_otbs {
        match chain.get_block(otb.root()).await {
            Ok(Some(block)) => {
                match validate_merge_block(chain, block.message(), AllowOptimisticImport::No).await
                {
                    Ok(()) => {
                        // merge transition block is valid, remove it from OTB
                        otb.remove_from_store::<T, _>(&chain.store)
                            .map_err(Error::StoreError)?;
                        info!(
                            chain.log,
                            "Validated merge transition block";
                            "block_root" => ?otb.root(),
                            "type" => "finalized"
                        );
                    }
                    // The block was not able to be verified by the EL. Leave the OTB in the
                    // database since the EL is likely still syncing and may verify the block
                    // later.
                    Err(BlockError::ExecutionPayloadError(
                        ExecutionPayloadError::UnverifiedNonOptimisticCandidate,
                    )) => (),
                    Err(BlockError::ExecutionPayloadError(
                        ExecutionPayloadError::InvalidTerminalPoWBlock { .. },
                    )) => {
                        // Finalized Merge Transition Block is Invalid! Kill the Client!
                        crit!(
                            chain.log,
                            "Finalized merge transition block is invalid!";
                            "msg" => "You must use the `--purge-db` flag to clear the database and restart sync. \
                            You may be on a hostile network.",
                            "block_hash" => ?block.canonical_root()
                        );
                        let mut shutdown_sender = chain.shutdown_sender();
                        if let Err(e) = shutdown_sender.try_send(ShutdownReason::Failure(
                            INVALID_FINALIZED_MERGE_TRANSITION_BLOCK_SHUTDOWN_REASON,
                        )) {
                            crit!(
                                chain.log,
                                "Failed to shut down client";
                                "error" => ?e,
                                "shutdown_reason" => INVALID_FINALIZED_MERGE_TRANSITION_BLOCK_SHUTDOWN_REASON
                            );
                        }
                    }
                    _ => {}
                }
            }
            Ok(None) => return Err(Error::NoBlockFound(otb)),
            // Our database has pruned the payload and the payload was unavailable on the EL since
            // the EL is still syncing or the payload is non-canonical.
            Err(BeaconChainError::BlockHashMissingFromExecutionLayer(_)) => (),
            Err(e) => return Err(Error::BeaconChain(e)),
        }
    }

    // attempt to validate any non-finalized canonical otb blocks
    for otb in unfinalized_canonical_otbs {
        match chain.get_block(otb.root()).await {
            Ok(Some(block)) => {
                match validate_merge_block(chain, block.message(), AllowOptimisticImport::No).await
                {
                    Ok(()) => {
                        // merge transition block is valid, remove it from OTB
                        otb.remove_from_store::<T, _>(&chain.store)
                            .map_err(Error::StoreError)?;
                        info!(
                            chain.log,
                            "Validated merge transition block";
                            "block_root" => ?otb.root(),
                            "type" => "not finalized"
                        );
                    }
                    // The block was not able to be verified by the EL. Leave the OTB in the
                    // database since the EL is likely still syncing and may verify the block
                    // later.
                    Err(BlockError::ExecutionPayloadError(
                        ExecutionPayloadError::UnverifiedNonOptimisticCandidate,
                    )) => (),
                    Err(BlockError::ExecutionPayloadError(
                        ExecutionPayloadError::InvalidTerminalPoWBlock { .. },
                    )) => {
                        // Unfinalized Merge Transition Block is Invalid -> Run process_invalid_execution_payload
                        warn!(
                            chain.log,
                            "Merge transition block invalid";
                            "block_root" => ?otb.root()
                        );
                        chain
                            .process_invalid_execution_payload(
                                &InvalidationOperation::InvalidateOne {
                                    block_root: *otb.root(),
                                },
                            )
                            .await
                            .map_err(|e| {
                                warn!(
                                    chain.log,
                                    "Error checking merge transition block";
                                    "error" => ?e,
                                    "location" => "process_invalid_execution_payload"
                                );
                                Error::BeaconChain(e)
                            })?;
                    }
                    _ => {}
                }
            }
            Ok(None) => return Err(Error::NoBlockFound(otb)),
            // Our database has pruned the payload and the payload was unavailable on the EL since
            // the EL is still syncing or the payload is non-canonical.
            Err(BeaconChainError::BlockHashMissingFromExecutionLayer(_)) => (),
            Err(e) => return Err(Error::BeaconChain(e)),
        }
    }

    Ok(())
}

/// Loop until any optimistically imported merge transition blocks have been verified and
/// the merge has been finalized.
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
                    "OTB verification service firing";
                );

                if !is_merge_transition_complete(
                    &chain.canonical_head.cached_head().snapshot.beacon_state,
                ) {
                    // We are pre-merge. Nothing to do yet.
                    continue;
                }

                // load all optimistically imported transition blocks from the database
                match load_optimistic_transition_blocks(chain.as_ref()) {
                    Ok(otbs) => {
                        if otbs.is_empty() {
                            if chain
                                .canonical_head
                                .fork_choice_read_lock()
                                .get_finalized_block()
                                .map_or(false, |block| {
                                    block.execution_status.is_execution_enabled()
                                })
                            {
                                // there are no optimistic blocks in the database, we can exit
                                // the service since the merge transition is finalized and we'll
                                // never see another transition block
                                break;
                            } else {
                                debug!(
                                    chain.log,
                                    "No optimistic transition blocks";
                                    "info" => "waiting for the merge transition to finalize"
                                )
                            }
                        }
                        if let Err(e) = validate_optimistic_transition_blocks(&chain, otbs).await {
                            warn!(
                                chain.log,
                                "Error while validating optimistic transition blocks";
                                "error" => ?e
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            chain.log,
                            "Error loading optimistic transition blocks";
                            "error" => ?e
                        );
                    }
                };
            }
            None => {
                error!(chain.log, "Failed to read slot clock");
                // If we can't read the slot clock, just wait another slot.
                sleep(chain.slot_clock.slot_duration()).await;
            }
        };
    }
    debug!(
        chain.log,
        "No optimistic transition blocks in database";
        "msg" => "shutting down OTB verification service"
    );
}
