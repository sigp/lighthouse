use super::{BeaconBlockHeader, BeaconState, EthSpec, FixedVector, Hash256, SyncCommittee};
use crate::{
    light_client_update::*, test_utils::TestRandom, AbstractExecPayload, Epoch, SignedBeaconBlock,
};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;

/// A LightClientBootstrap is the initializer we send over to lightclient nodes
/// that are trying to generate their basic storage when booting up.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TestRandom,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct LightClientBootstrap<T: EthSpec> {
    /// Requested beacon block header.
    pub header: BeaconBlockHeader,
    /// The `SyncCommittee` used in the requested period.
    pub current_sync_committee: Arc<SyncCommittee<T>>,
    /// Merkle proof for sync committee
    pub current_sync_committee_branch: FixedVector<Hash256, CurrentSyncCommitteeProofLen>,
}

impl<T: EthSpec> LightClientBootstrap<T> {
    pub fn from_beacon_state(beacon_state: &mut BeaconState<T>) -> Result<Self, Error> {
        let mut header = beacon_state.latest_block_header().clone();
        header.state_root = beacon_state.tree_hash_root();
        let current_sync_committee_branch =
            beacon_state.compute_merkle_proof(CURRENT_SYNC_COMMITTEE_INDEX)?;
        Ok(LightClientBootstrap {
            header,
            current_sync_committee: beacon_state.current_sync_committee()?.clone(),
            current_sync_committee_branch: FixedVector::new(current_sync_committee_branch)?,
        })
    }

    pub fn create_light_client_bootstrap<Payload: AbstractExecPayload<T>>(
        beacon_state: &mut BeaconState<T>,
        signed_beacon_block: SignedBeaconBlock<T, Payload>,
    ) -> Result<Self, Error> {
        if beacon_state.slot() != beacon_state.latest_block_header().slot {
            return Err(Error::CreateBootstrapError);
        }

        let mut header = beacon_state.latest_block_header().clone();

        header.state_root = beacon_state.tree_hash_root();

        if header.tree_hash_root() != signed_beacon_block.message().tree_hash_root() {
            return Err(Error::CreateBootstrapError);
        }

        let current_sync_committee_branch =
            beacon_state.compute_merkle_proof(CURRENT_SYNC_COMMITTEE_INDEX)?;

        Ok(LightClientBootstrap {
            header,
            current_sync_committee: beacon_state.current_sync_committee()?.clone(),
            current_sync_committee_branch: FixedVector::new(current_sync_committee_branch)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests!(LightClientBootstrap<MainnetEthSpec>);
}
