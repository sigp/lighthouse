use beacon_chain::{BeaconChain, BeaconChainTypes, WhenSlotSkipped};
use eth2::types::BlockId as CoreBlockId;
use std::str::FromStr;
use types::{Hash256, SignedBeaconBlock, Slot};

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
            CoreBlockId::Head => chain
                .head_info()
                .map(|head| head.block_root)
                .map_err(warp_utils::reject::beacon_chain_error),
            CoreBlockId::Genesis => Ok(chain.genesis_block_root),
            CoreBlockId::Finalized => chain
                .head_info()
                .map(|head| head.finalized_checkpoint.root)
                .map_err(warp_utils::reject::beacon_chain_error),
            CoreBlockId::Justified => chain
                .head_info()
                .map(|head| head.current_justified_checkpoint.root)
                .map_err(warp_utils::reject::beacon_chain_error),
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
            CoreBlockId::Root(root) => Ok(*root),
        }
    }

    /// Return the `SignedBeaconBlock` identified by `self`.
    pub fn block<T: BeaconChainTypes>(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<SignedBeaconBlock<T::EthSpec>, warp::Rejection> {
        match &self.0 {
            CoreBlockId::Head => chain
                .head_beacon_block()
                .map_err(warp_utils::reject::beacon_chain_error),
            CoreBlockId::Slot(slot) => {
                let root = self.root(chain)?;
                chain
                    .get_block(&root)
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
                    .get_block(&root)
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
}

impl FromStr for BlockId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CoreBlockId::from_str(s).map(Self)
    }
}
