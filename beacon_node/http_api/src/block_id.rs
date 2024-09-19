use crate::{state_id::checkpoint_slot_and_execution_optimistic, ExecutionOptimistic};
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes, WhenSlotSkipped};
use eth2::types::BlobIndicesQuery;
use eth2::types::BlockId as CoreBlockId;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use types::{
    BlobSidecarList, EthSpec, FixedBytesExtended, Hash256, SignedBeaconBlock,
    SignedBlindedBeaconBlock, Slot,
};

/// Wraps `eth2::types::BlockId` and provides a simple way to obtain a block or root for a given
/// `BlockId`.
#[derive(Debug)]
pub struct BlockId(pub CoreBlockId);

type Finalized = bool;

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
                    .map_err(warp_utils::reject::beacon_chain_error)?;
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
                    .map_err(warp_utils::reject::beacon_chain_error)?;
                let root = chain
                    .block_root_at_slot(*slot, WhenSlotSkipped::None)
                    .map_err(warp_utils::reject::beacon_chain_error)
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
                    .map_err(warp_utils::reject::beacon_chain_error)?
                {
                    let execution_optimistic = chain
                        .canonical_head
                        .fork_choice_read_lock()
                        .is_optimistic_or_invalid_block(root)
                        .map_err(BeaconChainError::ForkChoiceError)
                        .map_err(warp_utils::reject::beacon_chain_error)?;
                    let blinded_block = chain
                        .get_blinded_block(root)
                        .map_err(warp_utils::reject::beacon_chain_error)?
                        .ok_or_else(|| {
                            warp_utils::reject::custom_not_found(format!(
                                "beacon block with root {}",
                                root
                            ))
                        })?;
                    let block_slot = blinded_block.slot();
                    let finalized = chain
                        .is_finalized_block(root, block_slot)
                        .map_err(warp_utils::reject::beacon_chain_error)?;
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
            .map_err(warp_utils::reject::beacon_chain_error)
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
                    .map_err(warp_utils::reject::beacon_chain_error)?;
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
                    .map_err(warp_utils::reject::beacon_chain_error)?;
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
                    .map_err(warp_utils::reject::beacon_chain_error)
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
                    .map_err(warp_utils::reject::beacon_chain_error)
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

    #[allow(clippy::type_complexity)]
    pub fn get_blinded_block_and_blob_list_filtered<T: BeaconChainTypes>(
        &self,
        indices: BlobIndicesQuery,
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
        let blob_sidecar_list = if !blob_kzg_commitments.is_empty() {
            chain
                .store
                .get_blobs(&root)
                .map_err(|e| warp_utils::reject::beacon_chain_error(e.into()))?
                .ok_or_else(|| {
                    warp_utils::reject::custom_not_found(format!(
                        "no blobs stored for block {root}"
                    ))
                })?
        } else {
            BlobSidecarList::default()
        };

        let blob_sidecar_list_filtered = match indices.indices {
            Some(vec) => {
                let list = blob_sidecar_list
                    .into_iter()
                    .filter(|blob_sidecar| vec.contains(&blob_sidecar.index))
                    .collect();
                BlobSidecarList::new(list)
                    .map_err(|e| warp_utils::reject::custom_server_error(format!("{:?}", e)))?
            }
            None => blob_sidecar_list,
        };
        Ok((
            block,
            blob_sidecar_list_filtered,
            execution_optimistic,
            finalized,
        ))
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
