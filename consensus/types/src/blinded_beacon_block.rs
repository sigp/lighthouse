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
