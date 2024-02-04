use super::{BeaconState, EthSpec, FixedVector, Hash256, SyncCommittee};
use crate::{
    light_client_update::*, test_utils::TestRandom, ForkName, ForkVersionDeserialize,
    LightClientHeader,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use test_random_derive::TestRandom;

/// A LightClientBootstrap is the initializer we send over to light_client nodes
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
    /// The requested beacon block header.
    pub header: LightClientHeader,
    /// The `SyncCommittee` used in the requested period.
    pub current_sync_committee: Arc<SyncCommittee<T>>,
    /// Merkle proof for sync committee
    pub current_sync_committee_branch: FixedVector<Hash256, CurrentSyncCommitteeProofLen>,
}

impl<T: EthSpec> LightClientBootstrap<T> {
    pub fn from_beacon_state(beacon_state: &mut BeaconState<T>) -> Result<Self, Error> {
        let mut header = beacon_state.latest_block_header().clone();
        header.state_root = beacon_state.update_tree_hash_cache()?;
        let current_sync_committee_branch =
            beacon_state.compute_merkle_proof(CURRENT_SYNC_COMMITTEE_INDEX)?;
        Ok(LightClientBootstrap {
            header: header.into(),
            current_sync_committee: beacon_state.current_sync_committee()?.clone(),
            current_sync_committee_branch: FixedVector::new(current_sync_committee_branch)?,
        })
    }
}

impl<T: EthSpec> ForkVersionDeserialize for LightClientBootstrap<T> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Altair | ForkName::Merge => {
                Ok(serde_json::from_value::<LightClientBootstrap<T>>(value)
                    .map_err(serde::de::Error::custom))?
            }
            ForkName::Base | ForkName::Capella | ForkName::Deneb => {
                Err(serde::de::Error::custom(format!(
                    "LightClientBootstrap failed to deserialize: unsupported fork '{}'",
                    fork_name
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests!(LightClientBootstrap<MainnetEthSpec>);
}
