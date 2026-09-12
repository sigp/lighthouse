use crate::kzg_ext::ProgressiveKzgCommitments;
use crate::{Address, EthSpec, ExecutionBlockHash, ForkName, Hash256, SignedRoot, Slot};
use context_deserialize::context_deserialize;
use educe::Educe;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(Default, Debug, Clone, Serialize, Encode, Decode, Deserialize, TreeHash, Educe)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[educe(PartialEq, Hash)]
#[serde(bound = "E: EthSpec")]
#[context_deserialize(ForkName)]
// https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/beacon-chain.md#executionpayloadbid
#[tree_hash(
    struct_behaviour = "progressive_container",
    active_fields(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
)]
pub struct ExecutionPayloadBid<E: EthSpec> {
    pub parent_block_hash: ExecutionBlockHash,
    pub parent_block_root: Hash256,
    pub block_hash: ExecutionBlockHash,
    pub prev_randao: Hash256,
    #[serde(with = "serde_utils::address_hex")]
    pub fee_recipient: Address,
    #[serde(with = "serde_utils::quoted_u64")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub builder_index: u64,
    pub slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub value: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub execution_payment: u64,
    // [Modified in Gloas:EIP7688]
    pub blob_kzg_commitments: ProgressiveKzgCommitments,
    pub execution_requests_root: Hash256,
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub _phantom: PhantomData<E>,
}

impl<E: EthSpec> SignedRoot for ExecutionPayloadBid<E> {}

impl<E: EthSpec> ExecutionPayloadBid<E> {
    /// Returns the `tree_hash_root` of every field in declaration order, for use in progressive
    /// container Merkle proofs.
    pub fn field_roots(&self) -> Vec<Hash256> {
        vec![
            self.parent_block_hash.tree_hash_root(),
            self.parent_block_root.tree_hash_root(),
            self.block_hash.tree_hash_root(),
            self.prev_randao.tree_hash_root(),
            self.fee_recipient.tree_hash_root(),
            self.gas_limit.tree_hash_root(),
            self.builder_index.tree_hash_root(),
            self.slot.tree_hash_root(),
            self.value.tree_hash_root(),
            self.execution_payment.tree_hash_root(),
            self.blob_kzg_commitments.tree_hash_root(),
            self.execution_requests_root.tree_hash_root(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_and_tree_hash_tests!(ExecutionPayloadBid<MainnetEthSpec>);

    #[test]
    fn field_roots_match_root() {
        // Use a distinct value for every field so a swapped or missing entry in `field_roots`
        // changes the root.
        let bid = ExecutionPayloadBid::<MainnetEthSpec> {
            parent_block_hash: ExecutionBlockHash::from_root(Hash256::repeat_byte(1)),
            parent_block_root: Hash256::repeat_byte(2),
            block_hash: ExecutionBlockHash::from_root(Hash256::repeat_byte(3)),
            prev_randao: Hash256::repeat_byte(4),
            fee_recipient: Address::repeat_byte(5),
            gas_limit: 30_000_000,
            builder_index: 7,
            slot: crate::Slot::new(11),
            value: 42,
            execution_payment: 3,
            blob_kzg_commitments: ProgressiveKzgCommitments::new(vec![
                kzg::KzgCommitment::empty_for_testing(),
            ]),
            execution_requests_root: Hash256::repeat_byte(6),
            _phantom: PhantomData,
        };
        // The number of fields must match the `active_fields` attribute on the struct.
        let field_roots = bid.field_roots();
        assert_eq!(field_roots.len(), 12);

        let active_fields = merkle_proof::active_fields_all_active(field_roots.len()).unwrap();
        assert_eq!(
            merkle_proof::progressive_container_root(&field_roots, active_fields).unwrap(),
            bid.tree_hash_root()
        );
    }
}
