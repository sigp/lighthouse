use super::{BeaconBlockHeader, EthSpec, FixedVector, Hash256, Slot, SyncAggregate, SyncCommittee};
use crate::{light_client_update::*, test_utils::TestRandom, BeaconBlock, BeaconState, ChainSpec};
use safe_arith::ArithError;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::typenum::{U5, U6};
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;

/// A LightClientFinalityUpdate is the update lightclient request or received by a gossip that
/// signal a new finalized beacon block header for the light client sync protocol.
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct LightClientFinalityUpdate<T: EthSpec> {
    /// The last `BeaconBlockHeader` from the last attested block by the sync committee.
    pub attested_header: BeaconBlockHeader,
    /// The last `BeaconBlockHeader` from the last attested finalized block (end of epoch).
    pub finalized_header: BeaconBlockHeader,
    /// Merkle proof attesting finalized header.
    pub finality_branch: FixedVector<Hash256, FinalizedRootProofLen>,
    /// current sync aggreggate
    pub sync_aggregate: SyncAggregate<T>,
    /// Slot of the sync aggregated singature
    pub signature_slot: Slot,
}

impl<T: EthSpec> LightClientFinalityUpdate<T> {
    pub fn new(
        chain_spec: ChainSpec,
        beacon_state: BeaconState<T>,
        block: BeaconBlock<T>,
        attested_state: BeaconState<T>,
        finalized_block: BeaconBlock<T>,
    ) -> Result<Self, Error> {
        let altair_fork_epoch = chain_spec
            .altair_fork_epoch
            .ok_or(Error::AltairForkNotActive)?;
        if attested_state.slot().epoch(T::slots_per_epoch()) < altair_fork_epoch {
            return Err(Error::AltairForkNotActive);
        }

        let sync_aggregate = block.body().sync_aggregate()?;
        if sync_aggregate.num_set_bits() < chain_spec.min_sync_committee_participants as usize {
            return Err(Error::NotEnoughSyncCommitteeParticipants);
        }

        // Compute and validate attested header.
        let mut attested_header = attested_state.latest_block_header().clone();
        attested_header.state_root = attested_state.tree_hash_root();
        // Build finalized header from finalized block
        let finalized_header = BeaconBlockHeader {
            slot: finalized_block.slot(),
            proposer_index: finalized_block.proposer_index(),
            parent_root: finalized_block.parent_root(),
            state_root: finalized_block.state_root(),
            body_root: finalized_block.body_root(),
        };
        if finalized_header.tree_hash_root() != beacon_state.finalized_checkpoint().root {
            return Err(Error::InvalidFinalizedBlock);
        }
        // TODO(Giulio2002): compute proper merkle proofs.
        Ok(Self {
            attested_header: attested_header,
            finalized_header: finalized_header,
            finality_branch: FixedVector::new(vec![Hash256::zero(); FINALIZED_ROOT_PROOF_LEN])?,
            sync_aggregate: sync_aggregate.clone(),
            signature_slot: block.slot(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests!(LightClientFinalityUpdate<MainnetEthSpec>);
}
