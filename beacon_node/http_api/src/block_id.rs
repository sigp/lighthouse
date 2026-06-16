use crate::version::inconsistent_fork_rejection;
use crate::{ExecutionOptimistic, state_id::checkpoint_slot_and_execution_optimistic};
use beacon_chain::kzg_utils::reconstruct_blobs;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes, WhenSlotSkipped};
use eth2::beacon_response::{ExecutionOptimisticFinalizedMetadata, UnversionedResponse};
use eth2::types::BlockId as CoreBlockId;
use eth2::types::DataColumnIndicesQuery;
use eth2::types::{BlobIndicesQuery, BlobWrapper, BlobsVersionedHashesQuery};
use fixed_bytes::FixedBytesExtended;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use types::{
    BlobSidecarList, DataColumnSidecarList, EthSpec, ForkName, Hash256, SignedBeaconBlock,
    SignedBlindedBeaconBlock, Slot,
};
use warp::Rejection;

/// Wraps `eth2::types::BlockId` and provides a simple way to obtain a block or root for a given
/// `BlockId`.
#[derive(Debug)]
pub struct BlockId(pub CoreBlockId);

type Finalized = bool;

type DataColumnsResponse<T> = (
    DataColumnSidecarList<<T as BeaconChainTypes>::EthSpec>,
    ForkName,
    ExecutionOptimistic,
    Finalized,
);

impl BlockId {
    pub fn from_slot(slot: Slot) -> Self {
        Self(CoreBlockId::Slot(slot))
    }

    pub fn from_root(root: Hash256) -> Self {
        Self(CoreBlockId::Root(root))
    }

    /// Return the block root identified by `self`.
    pub fn root<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<(Hash256, ExecutionOptimistic, Finalized), warp::Rejection> {
        match &self.0 {
            CoreBlockId::Head => {
                let (cached_head, execution_status) = chain
                    .canonical_head
                    .head_and_execution_status()
                    .map_err(warp_utils::reject::unhandled_error)?;
                Ok((
                    cached_head.head_block_root(),
                    execution_status.is_optimistic_or_invalid(),
                    false,
                ))
            }
            CoreBlockId::Genesis => Ok((chain.genesis_block_root, false, true)),
            CoreBlockId::Finalized => {
                let finalized_checkpoint =
                    chain.canonical_head.cached_head().finalized_checkpoint();
                let (_slot, execution_optimistic) =
                    checkpoint_slot_and_execution_optimistic(chain, finalized_checkpoint)?;
                Ok((finalized_checkpoint.root, execution_optimistic, true))
            }
            CoreBlockId::Justified => {
                let justified_checkpoint =
                    chain.canonical_head.cached_head().justified_checkpoint();
                let (_slot, execution_optimistic) =
                    checkpoint_slot_and_execution_optimistic(chain, justified_checkpoint)?;
                Ok((justified_checkpoint.root, execution_optimistic, false))
            }
            CoreBlockId::Slot(slot) => {
                let execution_optimistic = chain
                    .is_optimistic_or_invalid_head()
                    .map_err(warp_utils::reject::unhandled_error)?;
                let root = chain
                    .block_root_at_slot(*slot, WhenSlotSkipped::None)
                    .map_err(warp_utils::reject::unhandled_error)
                    .and_then(|root_opt| {
                        root_opt.ok_or_else(|| {
                            warp_utils::reject::custom_not_found(format!(
                                "beacon block at slot {}",
                                slot
                            ))
                        })
                    })?;
                let finalized = *slot
                    <= chain
                        .canonical_head
                        .cached_head()
                        .finalized_checkpoint()
                        .epoch
                        .start_slot(T::EthSpec::slots_per_epoch());
                Ok((root, execution_optimistic, finalized))
            }
            CoreBlockId::Root(root) => {
                // This matches the behaviour of other consensus clients (e.g. Teku).
                if root == &Hash256::zero() {
                    return Err(warp_utils::reject::custom_not_found(format!(
                        "beacon block with root {}",
                        root
                    )));
                };
                if chain
                    .store
                    .block_exists(root)
                    .map_err(BeaconChainError::DBError)
                    .map_err(warp_utils::reject::unhandled_error)?
                {
                    let execution_optimistic = chain
                        .canonical_head
                        .fork_choice_read_lock()
                        .is_optimistic_or_invalid_block(root)
                        .map_err(BeaconChainError::ForkChoiceError)
                        .map_err(warp_utils::reject::unhandled_error)?;
                    let blinded_block = chain
                        .get_blinded_block(root)
                        .map_err(warp_utils::reject::unhandled_error)?
                        .ok_or_else(|| {
                            warp_utils::reject::custom_not_found(format!(
                                "beacon block with root {}",
                                root
                            ))
                        })?;
                    let block_slot = blinded_block.slot();
                    let finalized = chain
                        .is_finalized_block(root, block_slot)
                        .map_err(warp_utils::reject::unhandled_error)?;
                    Ok((*root, execution_optimistic, finalized))
                } else if chain.early_attester_cache.get_block(*root).is_some() {
                    // Fall back to the early attester cache for blocks that are in fork choice
                    // but haven't been written to disk yet.
                    let execution_optimistic = chain
                        .canonical_head
                        .fork_choice_read_lock()
                        .is_optimistic_or_invalid_block(root)
                        .unwrap_or(false);
                    Ok((*root, execution_optimistic, false))
                } else {
                    Err(warp_utils::reject::custom_not_found(format!(
                        "beacon block with root {}",
                        root
                    )))
                }
            }
        }
    }

    pub fn blinded_block_by_root<T: BeaconChainTypes>(
        root: &Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<Option<SignedBlindedBeaconBlock<T::EthSpec>>, warp::Rejection> {
        if let Some(block) = chain
            .get_blinded_block(root)
            .map_err(warp_utils::reject::unhandled_error)?
        {
            return Ok(Some(block));
        }
        // Fall back to the early attester cache for blocks that are in fork choice
        // but haven't been written to disk yet.
        Ok(chain
            .early_attester_cache
            .get_block(*root)
            .map(|b| b.clone_as_blinded()))
    }

    /// Return the `SignedBeaconBlock` identified by `self`.
    pub fn blinded_block<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<
        (
            SignedBlindedBeaconBlock<T::EthSpec>,
            ExecutionOptimistic,
            Finalized,
        ),
        warp::Rejection,
    > {
        match &self.0 {
            CoreBlockId::Head => {
                let (cached_head, execution_status) = chain
                    .canonical_head
                    .head_and_execution_status()
                    .map_err(warp_utils::reject::unhandled_error)?;
                Ok((
                    cached_head.snapshot.beacon_block.clone_as_blinded(),
                    execution_status.is_optimistic_or_invalid(),
                    false,
                ))
            }
            CoreBlockId::Slot(slot) => {
                let (root, execution_optimistic, finalized) = self.root(chain)?;
                BlockId::blinded_block_by_root(&root, chain).and_then(|block_opt| match block_opt {
                    Some(block) => {
                        if block.slot() != *slot {
                            return Err(warp_utils::reject::custom_not_found(format!(
                                "slot {} was skipped",
                                slot
                            )));
                        }
                        Ok((block, execution_optimistic, finalized))
                    }
                    None => Err(warp_utils::reject::custom_not_found(format!(
                        "beacon block with root {}",
                        root
                    ))),
                })
            }
            _ => {
                let (root, execution_optimistic, finalized) = self.root(chain)?;
                let block = BlockId::blinded_block_by_root(&root, chain).and_then(|root_opt| {
                    root_opt.ok_or_else(|| {
                        warp_utils::reject::custom_not_found(format!(
                            "beacon block with root {}",
                            root
                        ))
                    })
                })?;
                Ok((block, execution_optimistic, finalized))
            }
        }
    }

    /// Return the `SignedBeaconBlock` identified by `self`.
    pub async fn full_block<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<
        (
            Arc<SignedBeaconBlock<T::EthSpec>>,
            ExecutionOptimistic,
            Finalized,
        ),
        warp::Rejection,
    > {
        match &self.0 {
            CoreBlockId::Head => {
                let (cached_head, execution_status) = chain
                    .canonical_head
                    .head_and_execution_status()
                    .map_err(warp_utils::reject::unhandled_error)?;
                Ok((
                    cached_head.snapshot.beacon_block.clone(),
                    execution_status.is_optimistic_or_invalid(),
                    false,
                ))
            }
            CoreBlockId::Slot(slot) => {
                let (root, execution_optimistic, finalized) = self.root(chain)?;
                chain
                    .get_block(&root)
                    .await
                    .map_err(warp_utils::reject::unhandled_error)
                    .and_then(|block_opt| match block_opt {
                        Some(block) => {
                            if block.slot() != *slot {
                                return Err(warp_utils::reject::custom_not_found(format!(
                                    "slot {} was skipped",
                                    slot
                                )));
                            }
                            Ok((Arc::new(block), execution_optimistic, finalized))
                        }
                        None => Err(warp_utils::reject::custom_not_found(format!(
                            "beacon block with root {}",
                            root
                        ))),
                    })
            }
            _ => {
                let (root, execution_optimistic, finalized) = self.root(chain)?;
                let block_opt = chain
                    .get_block(&root)
                    .await
                    .map_err(warp_utils::reject::unhandled_error)?;
                let block = block_opt
                    .map(Arc::new)
                    .or_else(|| chain.early_attester_cache.get_block(root))
                    .ok_or_else(|| {
                        warp_utils::reject::custom_not_found(format!(
                            "beacon block with root {}",
                            root
                        ))
                    })?;
                Ok((block, execution_optimistic, finalized))
            }
        }
    }

    pub fn get_data_columns<T: BeaconChainTypes>(
        &self,
        query: DataColumnIndicesQuery,
        chain: &BeaconChain<T>,
    ) -> Result<DataColumnsResponse<T>, Rejection> {
        let (root, execution_optimistic, finalized) = self.root(chain)?;
        let block = BlockId::blinded_block_by_root(&root, chain)?.ok_or_else(|| {
            warp_utils::reject::custom_not_found(format!("beacon block with root {}", root))
        })?;

        let fork_name = chain.spec.fork_name_at_epoch(block.epoch());

        if !fork_name.fulu_enabled() {
            return Err(warp_utils::reject::custom_bad_request(
                "block is pre-Fulu and has no data columns".to_string(),
            ));
        }

        let data_column_sidecars = if let Some(indices) = query.indices {
            chain
                .get_data_columns_checking_all_caches(root, &indices)
                .map_err(warp_utils::reject::unhandled_error)?
        } else {
            chain
                .early_attester_cache
                .get_data_columns(root)
                .map(Ok)
                .unwrap_or_else(|| {
                    chain
                        .get_data_columns(&root, fork_name)
                        .map(|opt| opt.unwrap_or_default())
                })
                .map_err(warp_utils::reject::unhandled_error)?
        };

        let fork_name = block
            .fork_name(&chain.spec)
            .map_err(inconsistent_fork_rejection)?;

        Ok((
            data_column_sidecars,
            fork_name,
            execution_optimistic,
            finalized,
        ))
    }

    #[allow(clippy::type_complexity)]
    pub fn get_blinded_block_and_blob_list_filtered<T: BeaconChainTypes>(
        &self,
        query: BlobIndicesQuery,
        chain: &BeaconChain<T>,
    ) -> Result<
        (
            SignedBlindedBeaconBlock<T::EthSpec>,
            BlobSidecarList<T::EthSpec>,
            ExecutionOptimistic,
            Finalized,
        ),
        warp::Rejection,
    > {
        let (root, execution_optimistic, finalized) = self.root(chain)?;
        let block = BlockId::blinded_block_by_root(&root, chain)?.ok_or_else(|| {
            warp_utils::reject::custom_not_found(format!("beacon block with root {}", root))
        })?;

        // Error if the block is pre-Deneb and lacks blobs.
        let blob_kzg_commitments = block.message().body().blob_kzg_commitments().map_err(|_| {
            warp_utils::reject::custom_bad_request(
                "block is pre-Deneb and has no blobs".to_string(),
            )
        })?;

        // Return the `BlobSidecarList` identified by `self`.
        let max_blobs_per_block = chain.spec.max_blobs_per_block(block.epoch()) as usize;
        let blob_sidecar_list = if !blob_kzg_commitments.is_empty() {
            if chain.spec.is_peer_das_enabled_for_epoch(block.epoch()) {
                Self::get_blobs_from_data_columns(chain, root, query.indices, &block)?
            } else {
                Self::get_blobs(chain, root, query.indices, max_blobs_per_block)?
            }
        } else {
            BlobSidecarList::new(vec![], max_blobs_per_block)
                .map_err(|e| warp_utils::reject::custom_server_error(format!("{:?}", e)))?
        };

        Ok((block, blob_sidecar_list, execution_optimistic, finalized))
    }

    #[allow(clippy::type_complexity)]
    pub fn get_blobs_by_versioned_hashes<T: BeaconChainTypes>(
        &self,
        query: BlobsVersionedHashesQuery,
        chain: &BeaconChain<T>,
    ) -> Result<
        UnversionedResponse<Vec<BlobWrapper<T::EthSpec>>, ExecutionOptimisticFinalizedMetadata>,
        warp::Rejection,
    > {
        let (root, execution_optimistic, finalized) = self.root(chain)?;
        let block = BlockId::blinded_block_by_root(&root, chain)?.ok_or_else(|| {
            warp_utils::reject::custom_not_found(format!("beacon block with root {}", root))
        })?;

        // Error if the block is pre-Deneb and lacks blobs.
        let blob_kzg_commitments = block.message().body().blob_kzg_commitments().map_err(|_| {
            warp_utils::reject::custom_bad_request(
                "block is pre-Deneb and has no blobs".to_string(),
            )
        })?;

        let blob_indices_opt = query.versioned_hashes.map(|versioned_hashes| {
            versioned_hashes
                .iter()
                .flat_map(|versioned_hash| {
                    blob_kzg_commitments.iter().position(|commitment| {
                        let computed_hash = commitment.calculate_versioned_hash();
                        computed_hash == *versioned_hash
                    })
                })
                .map(|index| index as u64)
                .collect::<Vec<_>>()
        });

        let max_blobs_per_block = chain.spec.max_blobs_per_block(block.epoch()) as usize;
        let blob_sidecar_list = if !blob_kzg_commitments.is_empty() {
            if chain.spec.is_peer_das_enabled_for_epoch(block.epoch()) {
                Self::get_blobs_from_data_columns(chain, root, blob_indices_opt, &block)?
            } else {
                Self::get_blobs(chain, root, blob_indices_opt, max_blobs_per_block)?
            }
        } else {
            BlobSidecarList::new(vec![], max_blobs_per_block)
                .map_err(|e| warp_utils::reject::custom_server_error(format!("{:?}", e)))?
        };

        let blobs = blob_sidecar_list
            .into_iter()
            .map(|sidecar| BlobWrapper::<T::EthSpec> {
                blob: sidecar.blob.clone(),
            })
            .collect();

        Ok(UnversionedResponse {
            metadata: ExecutionOptimisticFinalizedMetadata {
                execution_optimistic: Some(execution_optimistic),
                finalized: Some(finalized),
            },
            data: blobs,
        })
    }

    fn get_blobs<T: BeaconChainTypes>(
        chain: &BeaconChain<T>,
        root: Hash256,
        indices: Option<Vec<u64>>,
        max_blobs_per_block: usize,
    ) -> Result<BlobSidecarList<T::EthSpec>, Rejection> {
        let blob_sidecar_list = chain
            .store
            .get_blobs(&root)
            .map_err(|e| warp_utils::reject::unhandled_error(BeaconChainError::from(e)))?
            .blobs()
            .ok_or_else(|| {
                warp_utils::reject::custom_not_found(format!("no blobs stored for block {root}"))
            })?;

        let blob_sidecar_list: Vec<_> = blob_sidecar_list.into_iter().collect();

        let blob_sidecar_list = match indices {
            Some(indices) => indices
                .into_iter()
                .filter_map(|i| blob_sidecar_list.get(i as usize).cloned())
                .collect(),
            None => blob_sidecar_list,
        };

        BlobSidecarList::new(blob_sidecar_list, max_blobs_per_block)
            .map_err(|e| warp_utils::reject::custom_server_error(format!("{:?}", e)))
    }

    fn get_blobs_from_data_columns<T: BeaconChainTypes>(
        chain: &BeaconChain<T>,
        root: Hash256,
        blob_indices: Option<Vec<u64>>,
        block: &SignedBlindedBeaconBlock<<T as BeaconChainTypes>::EthSpec>,
    ) -> Result<BlobSidecarList<T::EthSpec>, Rejection> {
        let column_indices = chain.store.get_data_column_keys(root).map_err(|e| {
            warp_utils::reject::custom_server_error(format!(
                "Error fetching data columns keys: {e:?}"
            ))
        })?;

        let num_found_column_keys = column_indices.len();
        let num_required_columns = T::EthSpec::number_of_columns() / 2;
        let is_blob_available = num_found_column_keys >= num_required_columns;
        let fork_name = chain.spec.fork_name_at_epoch(block.epoch());

        if is_blob_available {
            let data_columns = column_indices
                .into_iter()
                .filter_map(|column_index| {
                    match chain.get_data_column(&root, &column_index, fork_name) {
                        Ok(Some(data_column)) => Some(Ok(data_column)),
                        Ok(None) => None,
                        Err(e) => Some(Err(warp_utils::reject::unhandled_error(e))),
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;

            reconstruct_blobs(&chain.kzg, data_columns, blob_indices, block, &chain.spec).map_err(
                |e| {
                    warp_utils::reject::custom_server_error(format!(
                        "Error reconstructing data columns: {e:?}"
                    ))
                },
            )
        } else {
            Err(warp_utils::reject::custom_bad_request(format!(
                "Insufficient data columns to reconstruct blobs: required {num_required_columns}, but only {num_found_column_keys} were found. \
                You may need to run the beacon node with --supernode or --semi-supernode."
            )))
        }
    }
}

impl FromStr for BlockId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CoreBlockId::from_str(s).map(Self)
    }
}

impl fmt::Display for BlockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::{
        PayloadVerificationStatus,
        block_verification_types::AvailableBlockData,
        data_availability_checker::AvailableBlock,
        test_utils::{
            BeaconChainHarness, EphemeralHarnessType, fork_name_from_env,
            generate_data_column_sidecars_from_block,
        },
    };
    use std::time::Duration;
    use types::MinimalEthSpec;

    type TestHarness = BeaconChainHarness<EphemeralHarnessType<MinimalEthSpec>>;

    fn harness() -> TestHarness {
        BeaconChainHarness::builder(MinimalEthSpec)
            .default_spec()
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build()
    }

    #[tokio::test]
    async fn root_uses_early_attester_cache_for_unpersisted_block() {
        let Some(fork_name) = fork_name_from_env().filter(|fork_name| fork_name.fulu_enabled())
        else {
            return;
        };
        let harness = harness();
        let chain = &harness.chain;

        harness.execution_block_generator().set_min_blob_count(1);
        harness.advance_slot();

        let (block_contents, post_state) = harness
            .make_block(harness.get_current_state(), harness.get_current_slot())
            .await;
        let (block, _) = block_contents;
        let block_root = block.canonical_root();
        let block_fork_name = chain.spec.fork_name_at_epoch(block.epoch());

        assert_eq!(
            block_fork_name, fork_name,
            "precondition: test block must be produced at {fork_name:?}"
        );
        assert!(
            block.num_expected_blobs() > 0,
            "precondition: {fork_name:?} test block must have blobs that can be converted to data columns"
        );

        assert!(
            !chain.store.block_exists(&block_root).unwrap(),
            "precondition: test block must not be persisted"
        );
        assert!(
            chain.get_blinded_block(&block_root).unwrap().is_none(),
            "precondition: test block must not be retrievable from the store"
        );
        assert!(
            chain
                .get_data_columns(&block_root, block_fork_name)
                .unwrap()
                .is_none(),
            "precondition: test data columns must not be retrievable from the store"
        );
        assert!(
            !chain.block_is_known_to_fork_choice(&block_root),
            "precondition: test block must not be imported into fork choice yet"
        );

        let sampling_columns = chain.sampling_columns_for_epoch(block.epoch());
        let data_columns = generate_data_column_sidecars_from_block(&block, &chain.spec)
            .into_iter()
            .filter(|column| sampling_columns.contains(column.index()))
            .collect::<Vec<_>>();
        assert!(
            !data_columns.is_empty(),
            "precondition: {fork_name:?} test block must produce data columns"
        );

        let available_block = AvailableBlock::new(
            block.clone(),
            AvailableBlockData::new_with_data_columns(data_columns),
            &chain.data_availability_checker,
            chain.spec.clone(),
        )
        .unwrap();

        let current_slot = harness.get_current_slot();

        chain
            .canonical_head
            .fork_choice_write_lock()
            .on_block(
                current_slot,
                block.message(),
                block_root,
                Duration::ZERO,
                &post_state,
                PayloadVerificationStatus::Verified,
                &chain.spec,
            )
            .unwrap();

        assert!(
            chain.block_is_known_to_fork_choice(&block_root),
            "precondition: test block must be imported into fork choice"
        );
        assert!(
            !chain.store.block_exists(&block_root).unwrap(),
            "precondition: fork choice insertion must not persist the block"
        );

        let proto_block = chain
            .canonical_head
            .fork_choice_read_lock()
            .get_block(&block_root)
            .unwrap();

        chain
            .early_attester_cache
            .add_head_block(block_root, &available_block, proto_block, &post_state)
            .unwrap();

        let cached_data_columns = chain
            .early_attester_cache
            .get_data_columns(block_root)
            .expect("precondition: data columns must be cached");
        assert!(
            !cached_data_columns.is_empty(),
            "precondition: cached data columns must be non-empty"
        );

        assert_eq!(
            BlockId(CoreBlockId::Root(block_root)).root(chain).unwrap(),
            (block_root, false, false)
        );

        let (blinded_block, execution_optimistic, finalized) =
            BlockId(CoreBlockId::Root(block_root))
                .blinded_block(chain)
                .unwrap();
        assert_eq!(blinded_block.canonical_root(), block_root);
        assert_eq!(blinded_block.slot(), block.slot());
        assert!(!execution_optimistic);
        assert!(!finalized);

        let (data_columns, data_columns_fork_name, execution_optimistic, finalized) =
            BlockId(CoreBlockId::Root(block_root))
                .get_data_columns(DataColumnIndicesQuery { indices: None }, chain)
                .unwrap();
        assert_eq!(data_columns, cached_data_columns);
        assert_eq!(data_columns_fork_name, fork_name);
        assert!(!execution_optimistic);
        assert!(!finalized);

        chain.early_attester_cache.clear();

        assert!(
            BlockId(CoreBlockId::Root(block_root)).root(chain).is_err(),
            "root lookup should fail once the unpersisted block leaves the early attester cache"
        );
    }
}
