use crate::blinded_beacon_block_body::{
    BlindedBeaconBlockBodyAltair, BlindedBeaconBlockBodyBase, BlindedBeaconBlockBodyMerge,
    BlindedBeaconBlockBodyRef, BlindedBeaconBlockBodyRefMut,
};
use crate::test_utils::TestRandom;
use crate::*;
use bls::Signature;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, DecodeError};
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

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
            BeaconBlock::Base(b) => {
                let BeaconBlockBase {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                } = b;
                BlindedBeaconBlock::Base(BlindedBeaconBlockBase {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                })
            }
            BeaconBlock::Altair(b) => {
                let BeaconBlockAltair {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                } = b;
                BlindedBeaconBlock::Altair(BlindedBeaconBlockAltair {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                })
            }
            BeaconBlock::Merge(b) => {
                let BeaconBlockMerge {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                } = b;
                BlindedBeaconBlock::Merge(BlindedBeaconBlockMerge {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body,
                })
            }
        }
    }
}
