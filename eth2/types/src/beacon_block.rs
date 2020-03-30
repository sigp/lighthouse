use crate::test_utils::TestRandom;
use crate::*;
use bls::Signature;

use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// A block of the `BeaconChain`.
///
/// Spec v0.11.1
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct BeaconBlock<T: EthSpec> {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: Hash256,
    pub state_root: Hash256,
    pub body: BeaconBlockBody<T>,
}

impl<T: EthSpec> SignedRoot for BeaconBlock<T> {}

impl<T: EthSpec> BeaconBlock<T> {
    /// Returns an empty block to be used during genesis.
    ///
    /// Spec v0.11.1
    pub fn empty(spec: &ChainSpec) -> Self {
        BeaconBlock {
            slot: spec.genesis_slot,
            proposer_index: 0,
            parent_root: Hash256::zero(),
            state_root: Hash256::zero(),
            body: BeaconBlockBody {
                randao_reveal: Signature::empty_signature(),
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                    deposit_count: 0,
                },
                graffiti: [0; 32],
                proposer_slashings: VariableList::empty(),
                attester_slashings: VariableList::empty(),
                attestations: VariableList::empty(),
                deposits: VariableList::empty(),
                voluntary_exits: VariableList::empty(),
            },
        }
    }

    /// Returns the epoch corresponding to `self.slot`.
    pub fn epoch(&self) -> Epoch {
        self.slot.epoch(T::slots_per_epoch())
    }

    /// Returns the `tree_hash_root` of the block.
    ///
    /// Spec v0.11.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.tree_hash_root()[..])
    }

    /// Returns a full `BeaconBlockHeader` of this block.
    ///
    /// Note: This method is used instead of an `Into` impl to avoid a `Clone` of an entire block
    /// when you want to have the block _and_ the header.
    ///
    /// Note: performs a full tree-hash of `self.body`.
    ///
    /// Spec v0.11.1
    pub fn block_header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root: self.state_root,
            body_root: Hash256::from_slice(&self.body.tree_hash_root()[..]),
        }
    }

    /// Returns a "temporary" header, where the `state_root` is `Hash256::zero()`.
    ///
    /// Spec v0.11.1
    pub fn temporary_block_header(&self) -> BeaconBlockHeader {
        BeaconBlockHeader {
            state_root: Hash256::zero(),
            ..self.block_header()
        }
    }

    /// Signs `self`, producing a `SignedBeaconBlock`.
    pub fn sign(
        self,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedBeaconBlock<T> {
        let domain = spec.get_domain(
            self.epoch(),
            Domain::BeaconProposer,
            fork,
            genesis_validators_root,
        );
        let message = self.signing_root(domain);
        let signature = Signature::new(message.as_bytes(), secret_key);
        SignedBeaconBlock {
            message: self,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BeaconBlock<MainnetEthSpec>);
}
