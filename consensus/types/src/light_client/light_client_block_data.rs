use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{BitVector, FixedVector};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use typenum::U4;

use crate::{
    block::SignedBlindedBeaconBlock, core::{EthSpec, Hash256}, light_client::consts::SYNC_AGGREGATE_INDEX, state::BeaconStateError, sync_committee::SyncAggregate,
};

pub type SyncAggregateProofLen = U4;
pub type SyncAggregateBranch = FixedVector<Hash256, SyncAggregateProofLen>;

/// Information about a single slot within a `LightClientEpochData`.
///
/// For empty slots, this is `default` initialized.
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct LightClientBlockData<E: EthSpec> {
    pub proposer_index: u64,
    pub state_root: Hash256,
    pub sync_committee_bits: BitVector<E::SyncCommitteeSize>,
    /// `hash_tree_root(sync_aggregate.sync_committee_signature)`.
    pub sync_committee_signature_root: Hash256,
    /// Merkle proof for `sync_aggregate` in `BeaconBlockBody`, anchored at
    /// `hash_tree_root(body)`.
    pub sync_aggregate_branch: SyncAggregateBranch,
}

impl<E: EthSpec> LightClientBlockData<E> {
    /// Derive the per-slot data from a block. The caller is responsible for the
    /// epoch-level rules (e.g., which slots are populated, skipped slots, etc.).
    pub fn from_block(block: &SignedBlindedBeaconBlock<E>) -> Result<Self, BeaconStateError> {
        let body_ref = block.message().body();
        let sync_aggregate: &SyncAggregate<E> = body_ref.sync_aggregate()?;
        let sync_aggregate_branch = FixedVector::new(body_ref
            .block_body_merkle_proof(SYNC_AGGREGATE_INDEX)?)?;
        
        Ok(Self {
            proposer_index: block.message().proposer_index(),
            state_root: block.message().state_root(),
            sync_committee_bits: sync_aggregate.sync_committee_bits.clone(),
            sync_committee_signature_root: sync_aggregate.sync_committee_signature.tree_hash_root(),
            sync_aggregate_branch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block::{NUM_BEACON_BLOCK_BODY_HASH_TREE_ROOT_LEAVES, SignedBeaconBlock,
            SignedBeaconBlockAltair},
        light_client::consts::SYNC_AGGREGATE_PROOF_LEN,
        test_utils::test_arbitrary_instance,
        BlindedPayload, MainnetEthSpec,
    };
    use merkle_proof::verify_merkle_proof;
    use typenum::Unsigned;

    ssz_and_tree_hash_tests!(LightClientBlockData<MainnetEthSpec>);

    #[test]
    fn sync_aggregate_params() {
        assert!(2usize.pow(SYNC_AGGREGATE_PROOF_LEN as u32) <= SYNC_AGGREGATE_INDEX);
        assert!(2usize.pow(SYNC_AGGREGATE_PROOF_LEN as u32 + 1) > SYNC_AGGREGATE_INDEX);
        assert_eq!(SyncAggregateProofLen::to_usize(), SYNC_AGGREGATE_PROOF_LEN);
    }

    /// Confirms `sync_aggregate_branch` verifies against the block body root.
    /// This is the load-bearing check: if `SYNC_AGGREGATE_INDEX`/`SYNC_AGGREGATE_PROOF_LEN`
    /// were wrong, every other test in this file would still pass but this.
    #[test]
    fn sync_aggregate_branch_verifies_against_body_root() {
        // Force an Altair-fork block so `sync_aggregate()` is guaranteed present; a
        // generic `SignedBeaconBlock<E>` arbitrary instance could land on `Base`, which
        // has no sync aggregate at all.
        let inner: SignedBeaconBlockAltair<MainnetEthSpec, BlindedPayload<MainnetEthSpec>> =
            test_arbitrary_instance();
        let block: SignedBlindedBeaconBlock<MainnetEthSpec> = SignedBeaconBlock::Altair(inner);

        let data = LightClientBlockData::from_block(&block)
            .expect("Altair block always has a sync aggregate");

        let leaf = block.message().body().sync_aggregate().unwrap().tree_hash_root();
        let body_root = block.message().body_root();
        let field_index = SYNC_AGGREGATE_INDEX - NUM_BEACON_BLOCK_BODY_HASH_TREE_ROOT_LEAVES;

        assert!(verify_merkle_proof(
            leaf,
            &data.sync_aggregate_branch,
            SYNC_AGGREGATE_PROOF_LEN,
            field_index,
            body_root,
        ));

        // Sanity: a wrong leaf must not verify, so the assertion above isn't vacuously true.
        assert!(!verify_merkle_proof(
            Hash256::repeat_byte(0xff),
            &data.sync_aggregate_branch,
            SYNC_AGGREGATE_PROOF_LEN,
            field_index,
            body_root,
        ));
    }
}