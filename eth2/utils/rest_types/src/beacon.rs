//! A collection of REST API types for interaction with the beacon node.

use bls::PublicKeyBytes;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use types::beacon_state::EthSpec;
use types::{BeaconState, CommitteeIndex, Hash256, SignedBeaconBlock, Slot, Validator};

/// Information about a block that is at the head of a chain. May or may not represent the
/// canonical head.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct HeadBeaconBlock {
    pub beacon_block_root: Hash256,
    pub beacon_block_slot: Slot,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
#[serde(bound = "T: EthSpec")]
pub struct BlockResponse<T: EthSpec> {
    pub root: Hash256,
    pub beacon_block: SignedBeaconBlock<T>,
}

/// Information about the block and state that are at head of the beacon chain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct CanonicalHeadResponse {
    pub slot: Slot,
    pub block_root: Hash256,
    pub state_root: Hash256,
    pub finalized_slot: Slot,
    pub finalized_block_root: Hash256,
    pub justified_slot: Slot,
    pub justified_block_root: Hash256,
    pub previous_justified_slot: Slot,
    pub previous_justified_block_root: Hash256,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct ValidatorResponse {
    pub pubkey: PublicKeyBytes,
    pub validator_index: Option<usize>,
    pub balance: Option<u64>,
    pub validator: Option<Validator>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct ValidatorRequest {
    /// If set to `None`, uses the canonical head state.
    pub state_root: Option<Hash256>,
    pub pubkeys: Vec<PublicKeyBytes>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct Committee {
    pub slot: Slot,
    pub index: CommitteeIndex,
    pub committee: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, Decode)]
#[serde(bound = "T: EthSpec")]
pub struct StateResponse<T: EthSpec> {
    pub root: Hash256,
    pub beacon_state: BeaconState<T>,
}
