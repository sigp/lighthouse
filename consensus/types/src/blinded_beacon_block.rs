use crate::blinded_beacon_block_body::{
    BlindedBeaconBlockBodyAltair, BlindedBeaconBlockBodyBase, BlindedBeaconBlockBodyMerge,
};
use crate::*;
use serde_derive::{Deserialize, Serialize};
use superstruct::superstruct;

/// A block of the `BeaconChain`.
#[superstruct(
    variants(Base, Altair, Merge),
    variant_attributes(
        derive(Debug, PartialEq, Clone, Serialize, Deserialize,),
        serde(bound = "T: EthSpec", deny_unknown_fields),
    )
)]
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
pub struct BlindedBeaconBlock<T: EthSpec> {
    #[superstruct(getter(copy))]
    pub slot: Slot,
    #[superstruct(getter(copy))]
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub proposer_index: u64,
    #[superstruct(getter(copy))]
    pub parent_root: Hash256,
    #[superstruct(getter(copy))]
    pub state_root: Hash256,
    #[superstruct(only(Base), partial_getter(rename = "body_base"))]
    pub body: BlindedBeaconBlockBodyBase<T>,
    #[superstruct(only(Altair), partial_getter(rename = "body_altair"))]
    pub body: BlindedBeaconBlockBodyAltair<T>,
    #[superstruct(only(Merge), partial_getter(rename = "body_merge"))]
    pub body: BlindedBeaconBlockBodyMerge<T>,
}

impl<E: EthSpec> From<BeaconBlock<E, BlindedTransactions>> for BlindedBeaconBlock<E> {
    fn from(block: BeaconBlock<E, BlindedTransactions>) -> Self {
        match block {
            BeaconBlock::Base(b) => BlindedBeaconBlock::Base(b.into()),
            BeaconBlock::Altair(b) => BlindedBeaconBlock::Altair(b.into()),
            BeaconBlock::Merge(b) => BlindedBeaconBlock::Merge(b.into()),
        }
    }
}

impl<E: EthSpec> From<BeaconBlockBase<E, BlindedTransactions>> for BlindedBeaconBlockBase<E> {
    fn from(block: BeaconBlockBase<E, BlindedTransactions>) -> Self {
        let BeaconBlockBase {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        } = block;
        BlindedBeaconBlockBase {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body: body.into(),
        }
    }
}

impl<E: EthSpec> From<BeaconBlockAltair<E, BlindedTransactions>> for BlindedBeaconBlockAltair<E> {
    fn from(block: BeaconBlockAltair<E, BlindedTransactions>) -> Self {
        let BeaconBlockAltair {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        } = block;
        BlindedBeaconBlockAltair {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body: body.into(),
        }
    }
}

impl<E: EthSpec> From<BeaconBlockMerge<E, BlindedTransactions>> for BlindedBeaconBlockMerge<E> {
    fn from(block: BeaconBlockMerge<E, BlindedTransactions>) -> Self {
        let BeaconBlockMerge {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body,
        } = block;
        BlindedBeaconBlockMerge {
            slot,
            proposer_index,
            parent_root,
            state_root,
            body: body.into(),
        }
    }
}
