use super::{EthSpec, FixedVector, Hash256, Slot, SyncAggregate, SyncCommittee};
use crate::{
    beacon_state, test_utils::TestRandom, ForkName, ForkVersionDeserialize, LightClientHeader,
};
use safe_arith::ArithError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz::Decode;
use ssz_derive::Encode;
use ssz_types::typenum::{U4, U5, U6};
use std::sync::Arc;
use test_random_derive::TestRandom;

pub const FINALIZED_ROOT_INDEX: usize = 105;
pub const CURRENT_SYNC_COMMITTEE_INDEX: usize = 54;
pub const NEXT_SYNC_COMMITTEE_INDEX: usize = 55;
pub const EXECUTION_PAYLOAD_INDEX: usize = 25;

pub type FinalizedRootProofLen = U6;
pub type CurrentSyncCommitteeProofLen = U5;
pub type ExecutionPayloadProofLen = U4;

pub type NextSyncCommitteeProofLen = U5;

pub const FINALIZED_ROOT_PROOF_LEN: usize = 6;
pub const CURRENT_SYNC_COMMITTEE_PROOF_LEN: usize = 5;
pub const NEXT_SYNC_COMMITTEE_PROOF_LEN: usize = 5;
pub const EXECUTION_PAYLOAD_PROOF_LEN: usize = 4;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    SszTypesError(ssz_types::Error),
    BeaconStateError(beacon_state::Error),
    ArithError(ArithError),
    AltairForkNotActive,
    NotEnoughSyncCommitteeParticipants,
    MismatchingPeriods,
    InvalidFinalizedBlock,
    BeaconBlockBodyError,
}

impl From<ssz_types::Error> for Error {
    fn from(e: ssz_types::Error) -> Error {
        Error::SszTypesError(e)
    }
}

impl From<beacon_state::Error> for Error {
    fn from(e: beacon_state::Error) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Error {
        Error::ArithError(e)
    }
}

/// A LightClientUpdate is the update we request solely to either complete the bootstrapping process,
/// or to sync up to the last committee period, we need to have one ready for each ALTAIR period
/// we go over, note: there is no need to keep all of the updates from [ALTAIR_PERIOD, CURRENT_PERIOD].
#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, Encode, arbitrary::Arbitrary, TestRandom,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct LightClientUpdate<T: EthSpec> {
    /// The last `BeaconBlockHeader` from the last attested block by the sync committee.
    pub attested_header: LightClientHeader<T>,
    /// The `SyncCommittee` used in the next period.
    pub next_sync_committee: Arc<SyncCommittee<T>>,
    /// Merkle proof for next sync committee
    pub next_sync_committee_branch: FixedVector<Hash256, NextSyncCommitteeProofLen>,
    /// The last `BeaconBlockHeader` from the last attested finalized block (end of epoch).
    pub finalized_header: LightClientHeader<T>,
    /// Merkle proof attesting finalized header.
    pub finality_branch: FixedVector<Hash256, FinalizedRootProofLen>,
    /// current sync aggreggate
    pub sync_aggregate: SyncAggregate<T>,
    /// Slot of the sync aggregated singature
    pub signature_slot: Slot,
}

impl<T: EthSpec> ForkVersionDeserialize for LightClientUpdate<T> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Altair | ForkName::Merge | ForkName::Capella | ForkName::Deneb => {
                Ok(serde_json::from_value::<LightClientUpdate<T>>(value)
                    .map_err(serde::de::Error::custom))?
            }
            ForkName::Base => Err(serde::de::Error::custom(format!(
                "LightClientUpdate failed to deserialize: unsupported fork '{}'",
                fork_name
            ))),
        }
    }
}

impl<E: EthSpec> LightClientUpdate<E> {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<SyncCommittee<E>>()?;
        builder.register_type::<FixedVector<Hash256, NextSyncCommitteeProofLen>>()?;
        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<FixedVector<Hash256, FinalizedRootProofLen>>()?;
        builder.register_type::<SyncAggregate<E>>()?;
        builder.register_type::<Slot>()?;
        let mut decoder = builder.build()?;

        let attested_header = decoder
            .decode_next_with(|bytes| LightClientHeader::from_ssz_bytes(bytes, fork_name))?;
        let next_sync_committee = decoder.decode_next_with(SyncCommittee::from_ssz_bytes)?;
        let next_sync_committee_branch = decoder.decode_next_with(FixedVector::from_ssz_bytes)?;
        let finalized_header = decoder
            .decode_next_with(|bytes| LightClientHeader::from_ssz_bytes(bytes, fork_name))?;
        let finality_branch = decoder.decode_next_with(FixedVector::from_ssz_bytes)?;
        let sync_aggregate = decoder.decode_next_with(SyncAggregate::from_ssz_bytes)?;
        let signature_slot = decoder.decode_next_with(Slot::from_ssz_bytes)?;

        Ok(Self {
            attested_header,
            next_sync_committee: Arc::new(next_sync_committee),
            next_sync_committee_branch,
            finalized_header,
            finality_branch,
            sync_aggregate,
            signature_slot,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;
    use ssz_types::typenum::Unsigned;

    ssz_tests_by_fork!(LightClientUpdate<MainnetEthSpec>, ForkName::Deneb);

    #[test]
    fn finalized_root_params() {
        assert!(2usize.pow(FINALIZED_ROOT_PROOF_LEN as u32) <= FINALIZED_ROOT_INDEX);
        assert!(2usize.pow(FINALIZED_ROOT_PROOF_LEN as u32 + 1) > FINALIZED_ROOT_INDEX);
        assert_eq!(FinalizedRootProofLen::to_usize(), FINALIZED_ROOT_PROOF_LEN);
    }

    #[test]
    fn current_sync_committee_params() {
        assert!(
            2usize.pow(CURRENT_SYNC_COMMITTEE_PROOF_LEN as u32) <= CURRENT_SYNC_COMMITTEE_INDEX
        );
        assert!(
            2usize.pow(CURRENT_SYNC_COMMITTEE_PROOF_LEN as u32 + 1) > CURRENT_SYNC_COMMITTEE_INDEX
        );
        assert_eq!(
            CurrentSyncCommitteeProofLen::to_usize(),
            CURRENT_SYNC_COMMITTEE_PROOF_LEN
        );
    }

    #[test]
    fn next_sync_committee_params() {
        assert!(2usize.pow(NEXT_SYNC_COMMITTEE_PROOF_LEN as u32) <= NEXT_SYNC_COMMITTEE_INDEX);
        assert!(2usize.pow(NEXT_SYNC_COMMITTEE_PROOF_LEN as u32 + 1) > NEXT_SYNC_COMMITTEE_INDEX);
        assert_eq!(
            NextSyncCommitteeProofLen::to_usize(),
            NEXT_SYNC_COMMITTEE_PROOF_LEN
        );
    }
}
