use crate::version::inconsistent_fork_rejection;
use crate::{ExecutionOptimistic, state_id::checkpoint_slot_and_execution_optimistic};
use beacon_chain::kzg_utils::{reconstruct_blob_sidecars, reconstruct_blobs};
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
    BlobSidecarList, DataColumnSidecar, DataColumnSidecarList, EthSpec, ForkName, Hash256,
    SignedBeaconBlock, SignedBlindedBeaconBlock, Slot,
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
                let fallback_requires_fork_choice_check = if let Some((cached_slot, cached_root)) =
                    chain
                        .early_attester_cache
                        .get_head_block_root()
                        .filter(|(cached_slot, _)| cached_slot == slot)
                {
                    // Read the cache again before checking persistence. If the block is not
                    // persisted, this read occurs while its importer holds the fork choice write lock.
                    let cache_unchanged = chain.early_attester_cache.get_head_block_root()
                        == Some((cached_slot, cached_root));

                    if cache_unchanged {
                        let cached_root_is_persisted = chain
                            .store
                            .block_exists(&cached_root)
                            .map_err(BeaconChainError::DBError)
                            .map_err(warp_utils::reject::unhandled_error)?;

                        if !cached_root_is_persisted {
                            return Ok((cached_root, false, false));
                        }

                        // Block import locks fork choice before it locks the early attester cache.
                        // Use the same order to confirm the persisted cached head.
                        let fork_choice = chain.canonical_head.fork_choice_read_lock();
                        let cached_head = chain.early_attester_cache.get_head_block_root().filter(
                            |(current_slot, current_root)| {
                                current_slot == slot
                                    && *current_root
                                        == fork_choice.cached_fork_choice_view().head_block_root
                            },
                        );

                        if let Some((_, root)) = cached_head {
                            return Ok((root, false, false));
                        }
                    }

                    true
                } else {
                    false
                };

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
                if fallback_requires_fork_choice_check {
                    let fork_choice = chain.canonical_head.fork_choice_read_lock();
                    let current_head_root = fork_choice.cached_fork_choice_view().head_block_root;
                    if !fork_choice.is_descendant(root, current_head_root) {
                        return Err(warp_utils::reject::custom_not_found(format!(
                            "beacon block at slot {}",
                            slot
                        )));
                    }
                }
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
                    // Blocks in this cache are execution validated and not finalized.
                    Ok((*root, false, false))
                } else {
                    Err(warp_utils::reject::custom_not_found(format!(
                        "beacon block with root {}",
                        root
                    )))
                }
            }
        }
    }

    pub(crate) fn is_canonical<T: BeaconChainTypes>(
        &self,
        root: Hash256,
        slot: Slot,
        chain: &BeaconChain<T>,
    ) -> Result<bool, warp::Rejection> {
        // A successful slot lookup only returns the canonical block at that slot.
        if matches!(
            &self.0,
            CoreBlockId::Slot(requested_slot) if *requested_slot == slot
        ) {
            return Ok(true);
        }

        chain
            .block_root_at_slot(slot, WhenSlotSkipped::None)
            .map_err(warp_utils::reject::unhandled_error)
            .map(|canonical| canonical.is_some_and(|canonical| root == canonical))
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
                let data_columns =
                    Self::get_data_columns_for_blob_reconstruction(chain, root, &block)?;
                reconstruct_blob_sidecars(
                    &chain.kzg,
                    data_columns,
                    query.indices,
                    &block,
                    &chain.spec,
                )
                .map_err(|e| {
                    warp_utils::reject::custom_server_error(format!(
                        "Error reconstructing data columns: {e:?}"
                    ))
                })?
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

        let block_message = block.message();
        let blob_kzg_commitments = block_message.blob_kzg_commitments().ok_or_else(|| {
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
        let blobs = if !blob_kzg_commitments.is_empty() {
            if chain.spec.is_peer_das_enabled_for_epoch(block.epoch()) {
                let data_columns =
                    Self::get_data_columns_for_blob_reconstruction(chain, root, &block)?;
                reconstruct_blobs(
                    &chain.kzg,
                    data_columns,
                    blob_indices_opt,
                    blob_kzg_commitments.len(),
                )
                .map_err(|e| {
                    warp_utils::reject::custom_server_error(format!(
                        "Error reconstructing data columns: {e:?}"
                    ))
                })?
            } else {
                Self::get_blobs(chain, root, blob_indices_opt, max_blobs_per_block)?
                    .into_iter()
                    .map(|sidecar| sidecar.blob.clone())
                    .collect()
            }
        } else {
            vec![]
        };

        let blobs = blobs
            .into_iter()
            .map(|blob| BlobWrapper::<T::EthSpec> { blob })
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

    fn get_data_columns_for_blob_reconstruction<T: BeaconChainTypes>(
        chain: &BeaconChain<T>,
        root: Hash256,
        block: &SignedBlindedBeaconBlock<<T as BeaconChainTypes>::EthSpec>,
    ) -> Result<Vec<Arc<DataColumnSidecar<T::EthSpec>>>, Rejection> {
        let column_indices = chain.store.get_data_column_keys(root).map_err(|e| {
            warp_utils::reject::custom_server_error(format!(
                "Error fetching data columns keys: {e:?}"
            ))
        })?;

        let num_found_column_keys = column_indices.len();
        let num_required_columns = T::EthSpec::number_of_columns() / 2;
        let is_blob_available = num_found_column_keys >= num_required_columns;
        let fork_name = chain.spec.fork_name_at_epoch(block.epoch());

        if !is_blob_available {
            return Err(warp_utils::reject::custom_bad_request(format!(
                "Insufficient data columns to reconstruct blobs: required {num_required_columns}, but only {num_found_column_keys} were found. \
                You may need to run the beacon node with --supernode or --semi-supernode."
            )));
        }

        column_indices
            .into_iter()
            .filter_map(|column_index| {
                match chain.get_data_column(&root, &column_index, fork_name) {
                    Ok(Some(data_column)) => Some(Ok(data_column)),
                    Ok(None) => None,
                    Err(e) => Some(Err(warp_utils::reject::unhandled_error(e))),
                }
            })
            .collect::<Result<Vec<_>, _>>()
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
        custody_context::NodeCustodyType,
        data_availability_checker::AvailableBlock,
        test_utils::{
            BeaconChainHarness, EphemeralHarnessType, fork_name_from_env,
            generate_data_column_sidecars_from_block,
        },
    };
    use proto_array::Block as ProtoBlock;
    use std::sync::mpsc::Receiver;
    use std::thread::JoinHandle;
    use std::time::Duration;
    use types::{BeaconState, MinimalEthSpec};

    type TestHarness = BeaconChainHarness<EphemeralHarnessType<MinimalEthSpec>>;
    type TestChain = BeaconChain<EphemeralHarnessType<MinimalEthSpec>>;

    fn harness() -> TestHarness {
        BeaconChainHarness::builder(MinimalEthSpec)
            .default_spec()
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build()
    }

    fn gloas_supernode_harness() -> TestHarness {
        BeaconChainHarness::builder(MinimalEthSpec)
            .spec(Arc::new(
                ForkName::Gloas.make_genesis_spec(MinimalEthSpec::default_spec()),
            ))
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .node_custody_type(NodeCustodyType::Supernode)
            .build()
    }

    #[tokio::test]
    async fn get_blobs_by_versioned_hashes_post_gloas() {
        let harness = gloas_supernode_harness();
        harness.execution_block_generator().set_min_blob_count(2);
        harness.advance_slot();

        let slot = harness.get_current_slot();
        let (block_root, (block, _), _) = harness
            .add_block_at_slot(slot, harness.get_current_state())
            .await
            .expect("Gloas block should import");
        let block_root = Hash256::from(block_root);

        assert_eq!(block.fork_name_unchecked(), ForkName::Gloas);
        assert!(block.num_expected_blobs() >= 2);

        let all_blobs_response = BlockId(CoreBlockId::Head)
            .get_blobs_by_versioned_hashes(
                BlobsVersionedHashesQuery {
                    versioned_hashes: None,
                },
                &harness.chain,
            )
            .expect("Gloas head blobs should be retrievable");

        assert_eq!(all_blobs_response.data.len(), block.num_expected_blobs());

        let second_versioned_hash = block
            .message()
            .body()
            .signed_execution_payload_bid()
            .expect("Gloas block should contain an execution payload bid")
            .message
            .blob_kzg_commitments
            .get(1)
            .expect("test block should contain at least two blob commitments")
            .calculate_versioned_hash();
        let filtered_response = BlockId(CoreBlockId::Head)
            .get_blobs_by_versioned_hashes(
                BlobsVersionedHashesQuery {
                    versioned_hashes: Some(vec![second_versioned_hash]),
                },
                &harness.chain,
            )
            .expect("Gloas head blobs should be filterable by versioned hash");

        assert_eq!(filtered_response.data.len(), 1);
        assert_eq!(
            filtered_response
                .data
                .first()
                .expect("filtered response should contain one blob")
                .blob,
            all_blobs_response
                .data
                .get(1)
                .expect("unfiltered response should contain at least two blobs")
                .blob
        );
        assert_eq!(
            BlockId(CoreBlockId::Head).root(&harness.chain).unwrap().0,
            block_root
        );
    }

    struct UnpersistedBlock {
        available_block: AvailableBlock<MinimalEthSpec>,
        post_state: BeaconState<MinimalEthSpec>,
    }

    impl UnpersistedBlock {
        fn root(&self) -> Hash256 {
            self.available_block.block_root()
        }
    }

    async fn make_unpersisted_block(
        harness: &TestHarness,
        state: BeaconState<MinimalEthSpec>,
        slot: Slot,
    ) -> UnpersistedBlock {
        let (block_contents, post_state) = harness.make_block(state, slot).await;
        let (block, _) = block_contents;
        let available_block = AvailableBlock::new(
            block,
            AvailableBlockData::NoData,
            &harness.chain.custody_context,
        )
        .unwrap();
        UnpersistedBlock {
            available_block,
            post_state,
        }
    }

    fn add_block_to_fork_choice(
        harness: &TestHarness,
        block: &UnpersistedBlock,
        block_delay: Duration,
    ) -> ProtoBlock {
        let block_root = block.root();
        let mut fork_choice = harness.chain.canonical_head.fork_choice_write_lock();
        fork_choice
            .on_block(
                block.available_block.block().slot(),
                block.available_block.block().message(),
                block_root,
                block_delay,
                &block.post_state,
                PayloadVerificationStatus::Verified,
                &harness.chain.spec,
            )
            .unwrap();
        fork_choice.get_block(&block_root).unwrap()
    }

    fn cache_block(harness: &TestHarness, block: &UnpersistedBlock, proto_block: ProtoBlock) {
        harness
            .chain
            .early_attester_cache
            .add_head_block(
                block.root(),
                &block.available_block,
                proto_block,
                &block.post_state,
            )
            .unwrap();
    }

    fn spawn_slot_header_lookup(
        chain: Arc<TestChain>,
        slot: Slot,
    ) -> (JoinHandle<()>, Receiver<Hash256>) {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let request = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let block_id = BlockId(CoreBlockId::Slot(slot));
            let result = block_id.root(&chain).unwrap();
            assert!(!result.1);
            assert!(!result.2);
            let (block, _, _) = BlockId::from_root(result.0).blinded_block(&chain).unwrap();
            assert_eq!(block.canonical_root(), result.0);
            assert!(
                block_id
                    .is_canonical(result.0, block.slot(), &chain)
                    .unwrap()
            );
            result_tx.send(result.0).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        (request, result_rx)
    }

    #[tokio::test]
    async fn slot_uses_early_attester_cache_for_unpersisted_head() {
        let harness = harness();
        let chain = &harness.chain;
        harness
            .execution_block_generator()
            .set_generate_blobs(false);
        harness.advance_slot();

        let slot = harness.get_current_slot();
        let block = make_unpersisted_block(&harness, harness.get_current_state(), slot).await;
        let block_root = block.root();
        let proto_block = add_block_to_fork_choice(&harness, &block, Duration::ZERO);
        let mut fork_choice = chain.canonical_head.fork_choice_write_lock();
        let (head_root, _) = fork_choice.get_head(slot, &chain.spec).unwrap();
        assert_eq!(head_root, block_root, "precondition: block must be head");
        cache_block(&harness, &block, proto_block);

        assert!(
            !chain.store.block_exists(&block_root).unwrap(),
            "precondition: head block must not be persisted"
        );
        assert_eq!(
            chain
                .block_root_at_slot(slot, WhenSlotSkipped::None)
                .unwrap(),
            None,
            "precondition: persisted slot lookup must not resolve the new head"
        );

        let (request, result_rx) = spawn_slot_header_lookup(chain.clone(), slot);
        assert_eq!(
            result_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("unpersisted lookup must not wait for the fork choice write lock"),
            block_root
        );
        chain.early_attester_cache.clear();
        assert!(
            BlockId(CoreBlockId::Slot(slot))
                .is_canonical(block_root, slot, chain)
                .unwrap(),
            "slot lookup result must remain canonical after the cache is cleared"
        );
        drop(fork_choice);
        request.join().unwrap();
    }

    #[tokio::test]
    async fn slot_rejects_stale_cache_and_accepts_same_slot_replacement() {
        let harness = harness();
        let chain = &harness.chain;
        harness
            .execution_block_generator()
            .set_generate_blobs(false);
        harness.advance_slot();

        let slot = harness.get_current_slot();
        let state = harness.get_current_state();
        let block_a = make_unpersisted_block(&harness, state.clone(), slot).await;
        let block_b = make_unpersisted_block(&harness, state, slot).await;
        let block_root_a = block_a.root();
        let block_root_b = block_b.root();
        assert_ne!(
            block_root_a, block_root_b,
            "precondition: blocks must compete at the same slot"
        );

        // Import both blocks too late for proposer boost. Fork choice then selects the higher root.
        let (stale_block, replacement_block) = if block_root_a < block_root_b {
            (&block_a, &block_b)
        } else {
            (&block_b, &block_a)
        };

        let stale_proto_block = add_block_to_fork_choice(&harness, stale_block, Duration::MAX);
        let old_head_root = {
            let mut fork_choice = chain.canonical_head.fork_choice_write_lock();
            let (head_root, _) = fork_choice.get_head(slot, &chain.spec).unwrap();
            head_root
        };
        assert_eq!(
            old_head_root,
            stale_block.root(),
            "precondition: first block must become head"
        );

        cache_block(&harness, stale_block, stale_proto_block);
        chain
            .store
            .put_block(
                &stale_block.root(),
                stale_block.available_block.block().clone(),
            )
            .unwrap();
        assert_eq!(
            BlockId(CoreBlockId::Slot(slot)).root(chain).unwrap(),
            (stale_block.root(), false, false),
            "persisted cached head must resolve before the canonical snapshot is updated"
        );

        let replacement_proto_block =
            add_block_to_fork_choice(&harness, replacement_block, Duration::MAX);
        let mut fork_choice = chain.canonical_head.fork_choice_write_lock();
        let (new_head_root, _) = fork_choice.get_head(slot, &chain.spec).unwrap();
        assert_eq!(
            new_head_root,
            replacement_block.root(),
            "precondition: higher-root block must become head"
        );
        drop(fork_choice);

        let rejection = BlockId(CoreBlockId::Slot(slot)).root(chain).unwrap_err();
        assert!(
            rejection
                .find::<warp_utils::reject::CustomNotFound>()
                .is_some(),
            "stale same-slot cache entry must produce a not-found rejection"
        );

        cache_block(&harness, replacement_block, replacement_proto_block);
        chain
            .store
            .put_block(
                &replacement_block.root(),
                replacement_block.available_block.block().clone(),
            )
            .unwrap();
        assert_eq!(
            BlockId(CoreBlockId::Slot(slot)).root(chain).unwrap(),
            (replacement_block.root(), false, false),
            "same-slot replacement must be served"
        );
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

        let sampling_columns = chain
            .custody_context
            .sampling_columns_for_epoch(block.epoch());
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
            &chain.custody_context,
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
        assert!(
            !BlockId(CoreBlockId::Root(block_root))
                .is_canonical(block_root, block.slot(), chain)
                .unwrap(),
            "unpersisted root lookup must not be marked canonical"
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
