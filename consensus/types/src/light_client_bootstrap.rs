use super::{LightClientHeader, ChainSpec, SignedBlindedBeaconBlock, BeaconState, EthSpec, FixedVector, Hash256, SyncCommittee};
use crate::{beacon_state::Error as BeaconStateError, light_client_update::*, test_utils::TestRandom};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use ssz_types::Error as SszTypesError;

/// A LightClientBootstrap is the initializer we send over to lightclient nodes
/// that are trying to generate their basic storage when booting up.
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TestRandom)]
#[serde(bound = "T: EthSpec")]
pub struct LightClientBootstrap<T: EthSpec> {
    /// Requested light client header.
    pub header: LightClientHeader,
    /// The `SyncCommittee` used in the requested period.
    pub current_sync_committee: Arc<SyncCommittee<T>>,
    /// Merkle proof for sync committee
    pub current_sync_committee_branch: FixedVector<Hash256, CurrentSyncCommitteeProofLen>,
}

pub enum Error {
    AltairForkNotActive,
    InvalidState,
    BeaconStateError(BeaconStateError),
    SszTypesError(SszTypesError),
}

impl From<SszTypesError> for Error {
    fn from(e: SszTypesError) -> Error {
        Error::SszTypesError(e)
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl<T: EthSpec> LightClientBootstrap<T> {
    pub fn new(
        chain_spec: &ChainSpec,
        beacon_state: &mut BeaconState<T>,
        block: SignedBlindedBeaconBlock<T>,
    ) -> Result<Self, Error> {
        let altair_fork_epoch = chain_spec
            .altair_fork_epoch
            .ok_or(Error::AltairForkNotActive)?;
        if beacon_state.slot().epoch(T::slots_per_epoch()) < altair_fork_epoch {
            return Err(Error::AltairForkNotActive);
        }

        if beacon_state.slot() != beacon_state.latest_block_header().slot {
            return Err(Error::InvalidState);
        }
        let mut header = beacon_state.latest_block_header().clone();
        header.state_root = beacon_state.tree_hash_root();
        if header.tree_hash_root() != block.message().tree_hash_root() {
            return Err(Error::InvalidState);
        }
        let current_sync_committee_branch =
            beacon_state.compute_merkle_proof(CURRENT_SYNC_COMMITTEE_INDEX)?;
        Ok(LightClientBootstrap {
            header: LightClientHeader::from_block(block),
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
