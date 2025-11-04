use crate::version::inconsistent_fork_rejection;
use crate::{ExecutionOptimistic, state_id::checkpoint_slot_and_execution_optimistic};
use beacon_chain::kzg_utils::reconstruct_blobs;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes, WhenSlotSkipped};
use eth2::types::BlockId as CoreBlockId;
use eth2::types::DataColumnIndicesQuery;
use eth2::types::{BlobIndicesQuery, BlobWrapper, BlobsVersionedHashesQuery};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use types::{
    BlobSidecarList, DataColumnSidecarList, EthSpec, FixedBytesExtended, ForkName, Hash256,
    SignedBeaconBlock, SignedBlindedBeaconBlock, Slot, UnversionedResponse,
    beacon_response::ExecutionOptimisticFinalizedMetadata,
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
        chain
            .get_blinded_block(root)
            .map_err(warp_utils::reject::unhandled_error)
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
                chain
                    .get_block(&root)
                    .await
                    .map_err(warp_utils::reject::unhandled_error)
                    .and_then(|block_opt| {
                        block_opt
                            .map(|block| (Arc::new(block), execution_optimistic, finalized))
                            .ok_or_else(|| {
                                warp_utils::reject::custom_not_found(format!(
                                    "beacon block with root {}",
                                    root
                                ))
                            })
                    })
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

        if !chain.spec.is_peer_das_enabled_for_epoch(block.epoch()) {
            return Err(warp_utils::reject::custom_bad_request(
                "block is pre-Fulu and has no data columns".to_string(),
            ));
        }

        let data_column_sidecars = if let Some(indices) = query.indices {
            indices
                .iter()
                .filter_map(|index| chain.get_data_column(&root, index).transpose())
                .collect::<Result<DataColumnSidecarList<T::EthSpec>, _>>()
                .map_err(warp_utils::reject::unhandled_error)?
        } else {
            chain
                .get_data_columns(&root)
                .map_err(warp_utils::reject::unhandled_error)?
                .unwrap_or_default()
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

        let blob_sidecar_list_filtered = match indices {
            Some(vec) => {
                let list: Vec<_> = vec
                    .into_iter()
                    .flat_map(|index| blob_sidecar_list.get(index as usize).cloned())
                    .collect();

                BlobSidecarList::new(list, max_blobs_per_block)
                    .map_err(|e| warp_utils::reject::custom_server_error(format!("{:?}", e)))?
            }
            None => blob_sidecar_list,
        };

        Ok(blob_sidecar_list_filtered)
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

        if is_blob_available {
            let data_columns = column_indices
                .into_iter()
                .filter_map(
                    |column_index| match chain.get_data_column(&root, &column_index) {
                        Ok(Some(data_column)) => Some(Ok(data_column)),
                        Ok(None) => None,
                        Err(e) => Some(Err(warp_utils::reject::unhandled_error(e))),
                    },
                )
                .collect::<Result<Vec<_>, _>>()?;

            reconstruct_blobs(&chain.kzg, &data_columns, blob_indices, block, &chain.spec).map_err(
                |e| {
                    warp_utils::reject::custom_server_error(format!(
                        "Error reconstructing data columns: {e:?}"
                    ))
                },
            )
        } else {
            Err(warp_utils::reject::custom_server_error(format!(
                "Insufficient data columns to reconstruct blobs: required {num_required_columns}, but only {num_found_column_keys} were found."
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
