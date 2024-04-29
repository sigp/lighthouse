use super::{EthSpec, FixedVector, Hash256, Slot, SyncAggregate, SyncCommittee};
use crate::{
    beacon_state, test_utils::TestRandom, BeaconBlock, BeaconBlockHeader, BeaconState, ChainSpec,
    ForkName, ForkVersionDeserialize, LightClientHeaderAltair, LightClientHeaderCapella,
    LightClientHeaderDeneb, SignedBeaconBlock,
};
use derivative::Derivative;
use safe_arith::ArithError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz::Decode;
use ssz_derive::Decode;
use ssz_derive::Encode;
use ssz_types::typenum::{U4, U5, U6};
use std::sync::Arc;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

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
    MilhouseError(milhouse::Error),
    BeaconStateError(beacon_state::Error),
    ArithError(ArithError),
    AltairForkNotActive,
    NotEnoughSyncCommitteeParticipants,
    MismatchingPeriods,
    InvalidFinalizedBlock,
    BeaconBlockBodyError,
    InconsistentFork,
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

impl From<milhouse::Error> for Error {
    fn from(e: milhouse::Error) -> Error {
        Error::MilhouseError(e)
    }
}

/// A LightClientUpdate is the update we request solely to either complete the bootstrapping process,
/// or to sync up to the last committee period, we need to have one ready for each ALTAIR period
/// we go over, note: there is no need to keep all of the updates from [ALTAIR_PERIOD, CURRENT_PERIOD].
#[superstruct(
    variants(Altair, Capella, Deneb),
    variant_attributes(
        derive(
            Debug,
            Clone,
            PartialEq,
            Serialize,
            Deserialize,
            Derivative,
            Decode,
            Encode,
            TestRandom,
            arbitrary::Arbitrary,
            TreeHash,
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
    )
)]
#[derive(
    Debug, Clone, Serialize, Encode, TreeHash, Deserialize, arbitrary::Arbitrary, PartialEq,
)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct LightClientUpdate<E: EthSpec> {
    /// The last `BeaconBlockHeader` from the last attested block by the sync committee.
    #[superstruct(only(Altair), partial_getter(rename = "attested_header_altair"))]
    pub attested_header: LightClientHeaderAltair<E>,
    #[superstruct(only(Capella), partial_getter(rename = "attested_header_capella"))]
    pub attested_header: LightClientHeaderCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "attested_header_deneb"))]
    pub attested_header: LightClientHeaderDeneb<E>,
    /// The `SyncCommittee` used in the next period.
    pub next_sync_committee: Arc<SyncCommittee<E>>,
    /// Merkle proof for next sync committee
    pub next_sync_committee_branch: FixedVector<Hash256, NextSyncCommitteeProofLen>,
    /// The last `BeaconBlockHeader` from the last attested finalized block (end of epoch).
    #[superstruct(only(Altair), partial_getter(rename = "finalized_header_altair"))]
    pub finalized_header: LightClientHeaderAltair<E>,
    #[superstruct(only(Capella), partial_getter(rename = "finalized_header_capella"))]
    pub finalized_header: LightClientHeaderCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "finalized_header_deneb"))]
    pub finalized_header: LightClientHeaderDeneb<E>,
    /// Merkle proof attesting finalized header.
    pub finality_branch: FixedVector<Hash256, FinalizedRootProofLen>,
    /// current sync aggreggate
    pub sync_aggregate: SyncAggregate<E>,
    /// Slot of the sync aggregated signature
    pub signature_slot: Slot,
}

impl<E: EthSpec> ForkVersionDeserialize for LightClientUpdate<E> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        match fork_name {
            ForkName::Base => Err(serde::de::Error::custom(format!(
                "LightClientUpdate failed to deserialize: unsupported fork '{}'",
                fork_name
            ))),
            _ => Ok(serde_json::from_value::<LightClientUpdate<E>>(value)
                .map_err(serde::de::Error::custom))?,
        }
    }
}

impl<E: EthSpec> LightClientUpdate<E> {
    pub fn new(
        beacon_state: BeaconState<E>,
        block: BeaconBlock<E>,
        attested_state: &mut BeaconState<E>,
        attested_block: &SignedBeaconBlock<E>,
        finalized_block: &SignedBeaconBlock<E>,
        chain_spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let sync_aggregate = block.body().sync_aggregate()?;
        if sync_aggregate.num_set_bits() < chain_spec.min_sync_committee_participants as usize {
            return Err(Error::NotEnoughSyncCommitteeParticipants);
        }

        let signature_period = block.epoch().sync_committee_period(chain_spec)?;
        // Compute and validate attested header.
        let mut attested_header = attested_state.latest_block_header().clone();
        attested_header.state_root = attested_state.tree_hash_root();
        let attested_period = attested_header
            .slot
            .epoch(E::slots_per_epoch())
            .sync_committee_period(chain_spec)?;
        if attested_period != signature_period {
            return Err(Error::MismatchingPeriods);
        }
        // Build finalized header from finalized block
        let finalized_header = BeaconBlockHeader {
            slot: finalized_block.slot(),
            proposer_index: finalized_block.message().proposer_index(),
            parent_root: finalized_block.parent_root(),
            state_root: finalized_block.state_root(),
            body_root: finalized_block.message().body_root(),
        };
        if finalized_header.tree_hash_root() != beacon_state.finalized_checkpoint().root {
            return Err(Error::InvalidFinalizedBlock);
        }
        let next_sync_committee_branch =
            attested_state.compute_merkle_proof(NEXT_SYNC_COMMITTEE_INDEX)?;
        let finality_branch = attested_state.compute_merkle_proof(FINALIZED_ROOT_INDEX)?;

        let light_client_update = match attested_block
            .fork_name(chain_spec)
            .map_err(|_| Error::InconsistentFork)?
        {
            ForkName::Base => return Err(Error::AltairForkNotActive),
            ForkName::Altair | ForkName::Bellatrix => {
                let attested_header =
                    LightClientHeaderAltair::block_to_light_client_header(attested_block)?;
                let finalized_header =
                    LightClientHeaderAltair::block_to_light_client_header(finalized_block)?;
                Self::Altair(LightClientUpdateAltair {
                    attested_header,
                    next_sync_committee: attested_state.next_sync_committee()?.clone(),
                    next_sync_committee_branch: FixedVector::new(next_sync_committee_branch)?,
                    finalized_header,
                    finality_branch: FixedVector::new(finality_branch)?,
                    sync_aggregate: sync_aggregate.clone(),
                    signature_slot: block.slot(),
                })
            }
            ForkName::Capella => {
                let attested_header =
                    LightClientHeaderCapella::block_to_light_client_header(attested_block)?;
                let finalized_header =
                    LightClientHeaderCapella::block_to_light_client_header(finalized_block)?;
                Self::Capella(LightClientUpdateCapella {
                    attested_header,
                    next_sync_committee: attested_state.next_sync_committee()?.clone(),
                    next_sync_committee_branch: FixedVector::new(next_sync_committee_branch)?,
                    finalized_header,
                    finality_branch: FixedVector::new(finality_branch)?,
                    sync_aggregate: sync_aggregate.clone(),
                    signature_slot: block.slot(),
                })
            }
            ForkName::Deneb | ForkName::Electra => {
                let attested_header =
                    LightClientHeaderDeneb::block_to_light_client_header(attested_block)?;
                let finalized_header =
                    LightClientHeaderDeneb::block_to_light_client_header(finalized_block)?;
                Self::Deneb(LightClientUpdateDeneb {
                    attested_header,
                    next_sync_committee: attested_state.next_sync_committee()?.clone(),
                    next_sync_committee_branch: FixedVector::new(next_sync_committee_branch)?,
                    finalized_header,
                    finality_branch: FixedVector::new(finality_branch)?,
                    sync_aggregate: sync_aggregate.clone(),
                    signature_slot: block.slot(),
                })
            }
        };

        Ok(light_client_update)
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let update = match fork_name {
            ForkName::Altair | ForkName::Bellatrix => {
                Self::Altair(LightClientUpdateAltair::from_ssz_bytes(bytes)?)
            }
            ForkName::Capella => Self::Capella(LightClientUpdateCapella::from_ssz_bytes(bytes)?),
            ForkName::Deneb | ForkName::Electra => {
                Self::Deneb(LightClientUpdateDeneb::from_ssz_bytes(bytes)?)
            }
            ForkName::Base => {
                return Err(ssz::DecodeError::BytesInvalid(format!(
                    "LightClientUpdate decoding for {fork_name} not implemented"
                )))
            }
        };

        Ok(update)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;
    use ssz_types::typenum::Unsigned;

    ssz_tests!(LightClientUpdateDeneb<MainnetEthSpec>);

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
