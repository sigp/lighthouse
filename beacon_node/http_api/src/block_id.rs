use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes, WhenSlotSkipped};
use eth2::types::BlockId as CoreBlockId;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use types::{BlindedPayload, Hash256, SignedBeaconBlock, Slot};

/// Wraps `eth2::types::BlockId` and provides a simple way to obtain a block or root for a given
/// `BlockId`.
#[derive(Debug)]
pub struct BlockId(pub CoreBlockId);

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
    ) -> Result<Hash256, warp::Rejection> {
        match &self.0 {
            CoreBlockId::Head => Ok(chain.canonical_head.cached_head().head_block_root()),
            CoreBlockId::Genesis => Ok(chain.genesis_block_root),
            CoreBlockId::Finalized => Ok(chain
                .canonical_head
                .cached_head()
                .finalized_checkpoint()
                .root),
            CoreBlockId::Justified => Ok(chain
                .canonical_head
                .cached_head()
                .justified_checkpoint()
                .root),
            CoreBlockId::Slot(slot) => chain
                .block_root_at_slot(*slot, WhenSlotSkipped::None)
                .map_err(warp_utils::reject::beacon_chain_error)
                .and_then(|root_opt| {
                    root_opt.ok_or_else(|| {
                        warp_utils::reject::custom_not_found(format!(
                            "beacon block at slot {}",
                            slot
                        ))
                    })
                }),
            CoreBlockId::Root(root) => {
                if root == &Hash256::zero() {
                    return Err(warp_utils::reject::custom_not_found(format!(
                        "beacon block with root {}",
                        root
                    )));
                };
                chain
                    .store
                    .get_blinded_block(root)
                    .map_err(BeaconChainError::DBError)
                    .map_err(warp_utils::reject::beacon_chain_error)?
                    .map(|block| block.canonical_root())
                    .ok_or_else(|| {
                        warp_utils::reject::custom_not_found(format!(
                            "beacon block with root {}",
                            root
                        ))
                    })
            }
        }
    }

    /// Return the `SignedBeaconBlock` identified by `self`.
    pub fn blinded_block<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<SignedBeaconBlock<T::EthSpec, BlindedPayload<T::EthSpec>>, warp::Rejection> {
        match &self.0 {
            CoreBlockId::Head => Ok(chain.head_beacon_block().clone_as_blinded()),
            CoreBlockId::Slot(slot) => {
                let root = self.root(chain)?;
                chain
                    .get_blinded_block(&root)
                    .map_err(warp_utils::reject::beacon_chain_error)
                    .and_then(|block_opt| match block_opt {
                        Some(block) => {
                            if block.slot() != *slot {
                                return Err(warp_utils::reject::custom_not_found(format!(
                                    "slot {} was skipped",
                                    slot
                                )));
                            }
                            Ok(block)
                        }
                        None => Err(warp_utils::reject::custom_not_found(format!(
                            "beacon block with root {}",
                            root
                        ))),
                    })
            }
            _ => {
                let root = self.root(chain)?;
                chain
                    .get_blinded_block(&root)
                    .map_err(warp_utils::reject::beacon_chain_error)
                    .and_then(|root_opt| {
                        root_opt.ok_or_else(|| {
                            warp_utils::reject::custom_not_found(format!(
                                "beacon block with root {}",
                                root
                            ))
                        })
                    })
            }
        }
    }

    /// Return the `SignedBeaconBlock` identified by `self`.
    pub async fn full_block<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<Arc<SignedBeaconBlock<T::EthSpec>>, warp::Rejection> {
        match &self.0 {
            CoreBlockId::Head => Ok(chain.head_beacon_block()),
            CoreBlockId::Slot(slot) => {
                let root = self.root(chain)?;
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
                            Ok(Arc::new(block))
                        }
                        None => Err(warp_utils::reject::custom_not_found(format!(
                            "beacon block with root {}",
                            root
                        ))),
                    })
            }
            _ => {
                let root = self.root(chain)?;
                chain
                    .get_block(&root)
                    .await
                    .map_err(warp_utils::reject::beacon_chain_error)
                    .and_then(|block_opt| {
                        block_opt.map(Arc::new).ok_or_else(|| {
                            warp_utils::reject::custom_not_found(format!(
                                "beacon block with root {}",
                                root
                            ))
                        })
                    })
            }
        }
    }

    /// Returns the `block` along with the `execution_optimistic` value identified by `self`.
    pub async fn full_block_and_execution_optimistic<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<(Arc<SignedBeaconBlock<T::EthSpec>>, bool), warp::Rejection> {
        let block = self.full_block(chain).await?;
        let execution_optimistic = match self.0 {
            // Genesis block is inherently verified.
            CoreBlockId::Genesis => false,
            // Head, Finalized and Justified are determined based on their respective statuses.
            CoreBlockId::Head => chain
                .is_optimistic_head_block(&block)
                .map_err(warp_utils::reject::beacon_chain_error)?,
            // Note that `Justified` should always be present in fork choice,
            // so using `is_optimistic_head_block` should be fine here. Although there is a small
            // risk of `Justified` being pruned from the fork choice store before its status is
            // computed.
            CoreBlockId::Justified => chain
                .is_optimistic_head_block(&block)
                .map_err(warp_utils::reject::beacon_chain_error)?,
            // Since `is_optimistic_block` falls back to the status of the finalized block, using
            // it should minimize the impacts of the possible race condition.
            CoreBlockId::Finalized => chain
                .is_optimistic_block(&block)
                .map_err(warp_utils::reject::beacon_chain_error)?,
            // If the slot is supplied we cannot use `block`. Instead we compute the
            // head and use that to determine the status.
            CoreBlockId::Slot(_) => chain
                .is_optimistic_head()
                .map_err(warp_utils::reject::beacon_chain_error)?,
            // If the root is explicitly given, compute its status directly.
            CoreBlockId::Root(_) => chain
                .is_optimistic_block(&block)
                .map_err(warp_utils::reject::beacon_chain_error)?,
        };
        Ok((block, execution_optimistic))
    }

    /// Convenience function to compute `execution_optimistic` when `block` is not desired.
    pub async fn is_execution_optimistic<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<bool, warp::Rejection> {
        self.full_block_and_execution_optimistic(chain)
            .await
            .map(|(_, execution_optimistic)| execution_optimistic)
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
