use super::{EthSpec, FixedVector, Hash256, Slot, SyncAggregate, SyncCommittee};
use crate::light_client_header::LightClientHeaderElectra;
use crate::LightClientHeader;
use crate::{
    beacon_state, test_utils::TestRandom, ChainSpec, Epoch, ForkName, ForkVersionDeserialize,
    LightClientHeaderAltair, LightClientHeaderCapella, LightClientHeaderDeneb,
    SignedBlindedBeaconBlock,
};
use derivative::Derivative;
use safe_arith::ArithError;
use safe_arith::SafeArith;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use ssz::{Decode, Encode};
use ssz_derive::Decode;
use ssz_derive::Encode;
use ssz_types::typenum::{U4, U5, U6, U7};
use std::sync::Arc;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub const FINALIZED_ROOT_INDEX: usize = 105;
pub const CURRENT_SYNC_COMMITTEE_INDEX: usize = 54;
pub const NEXT_SYNC_COMMITTEE_INDEX: usize = 55;
pub const EXECUTION_PAYLOAD_INDEX: usize = 25;

pub const FINALIZED_ROOT_INDEX_ELECTRA: usize = 169;
pub const CURRENT_SYNC_COMMITTEE_INDEX_ELECTRA: usize = 86;
pub const NEXT_SYNC_COMMITTEE_INDEX_ELECTRA: usize = 87;

pub type FinalizedRootProofLen = U6;
pub type CurrentSyncCommitteeProofLen = U5;
pub type ExecutionPayloadProofLen = U4;
pub type NextSyncCommitteeProofLen = U5;

pub type FinalizedRootProofLenElectra = U7;
pub type CurrentSyncCommitteeProofLenElectra = U6;
pub type NextSyncCommitteeProofLenElectra = U6;

pub const FINALIZED_ROOT_PROOF_LEN: usize = 6;
pub const CURRENT_SYNC_COMMITTEE_PROOF_LEN: usize = 5;
pub const NEXT_SYNC_COMMITTEE_PROOF_LEN: usize = 5;
pub const EXECUTION_PAYLOAD_PROOF_LEN: usize = 4;

pub const FINALIZED_ROOT_PROOF_LEN_ELECTRA: usize = 7;
pub const NEXT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA: usize = 6;
pub const CURRENT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA: usize = 6;

pub type MerkleProof = Vec<Hash256>;
// Max light client updates by range request limits
// spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/p2p-interface.md#configuration
pub const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u64 = 128;

type FinalityBranch = FixedVector<Hash256, FinalizedRootProofLen>;
type FinalityBranchElectra = FixedVector<Hash256, FinalizedRootProofLenElectra>;
type NextSyncCommitteeBranch = FixedVector<Hash256, NextSyncCommitteeProofLen>;

type NextSyncCommitteeBranchElectra = FixedVector<Hash256, NextSyncCommitteeProofLenElectra>;

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
    variants(Altair, Capella, Deneb, Electra),
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
    #[superstruct(only(Electra), partial_getter(rename = "attested_header_electra"))]
    pub attested_header: LightClientHeaderElectra<E>,
    /// The `SyncCommittee` used in the next period.
    pub next_sync_committee: Arc<SyncCommittee<E>>,
    // Merkle proof for next sync committee
    #[superstruct(
        only(Altair, Capella, Deneb),
        partial_getter(rename = "next_sync_committee_branch_altair")
    )]
    pub next_sync_committee_branch: NextSyncCommitteeBranch,
    #[superstruct(
        only(Electra),
        partial_getter(rename = "next_sync_committee_branch_electra")
    )]
    pub next_sync_committee_branch: NextSyncCommitteeBranchElectra,
    /// The last `BeaconBlockHeader` from the last attested finalized block (end of epoch).
    #[superstruct(only(Altair), partial_getter(rename = "finalized_header_altair"))]
    pub finalized_header: LightClientHeaderAltair<E>,
    #[superstruct(only(Capella), partial_getter(rename = "finalized_header_capella"))]
    pub finalized_header: LightClientHeaderCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "finalized_header_deneb"))]
    pub finalized_header: LightClientHeaderDeneb<E>,
    #[superstruct(only(Electra), partial_getter(rename = "finalized_header_electra"))]
    pub finalized_header: LightClientHeaderElectra<E>,
    /// Merkle proof attesting finalized header.
    #[superstruct(
        only(Altair, Capella, Deneb),
        partial_getter(rename = "finality_branch_altair")
    )]
    pub finality_branch: FinalityBranch,
    #[superstruct(only(Electra), partial_getter(rename = "finality_branch_electra"))]
    pub finality_branch: FinalityBranchElectra,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sync_aggregate: &SyncAggregate<E>,
        block_slot: Slot,
        next_sync_committee: Arc<SyncCommittee<E>>,
        next_sync_committee_branch: Vec<Hash256>,
        finality_branch: Vec<Hash256>,
        attested_block: &SignedBlindedBeaconBlock<E>,
        finalized_block: Option<&SignedBlindedBeaconBlock<E>>,
        chain_spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let light_client_update = match attested_block
            .fork_name(chain_spec)
            .map_err(|_| Error::InconsistentFork)?
        {
            ForkName::Base => return Err(Error::AltairForkNotActive),
            ForkName::Altair | ForkName::Bellatrix => {
                let attested_header =
                    LightClientHeaderAltair::block_to_light_client_header(attested_block)?;

                let finalized_header = if let Some(finalized_block) = finalized_block {
                    LightClientHeaderAltair::block_to_light_client_header(finalized_block)?
                } else {
                    LightClientHeaderAltair::default()
                };

                Self::Altair(LightClientUpdateAltair {
                    attested_header,
                    next_sync_committee,
                    next_sync_committee_branch: next_sync_committee_branch.into(),
                    finalized_header,
                    finality_branch: finality_branch.into(),
                    sync_aggregate: sync_aggregate.clone(),
                    signature_slot: block_slot,
                })
            }
            ForkName::Capella => {
                let attested_header =
                    LightClientHeaderCapella::block_to_light_client_header(attested_block)?;

                let finalized_header = if let Some(finalized_block) = finalized_block {
                    LightClientHeaderCapella::block_to_light_client_header(finalized_block)?
                } else {
                    LightClientHeaderCapella::default()
                };

                Self::Capella(LightClientUpdateCapella {
                    attested_header,
                    next_sync_committee,
                    next_sync_committee_branch: next_sync_committee_branch.into(),
                    finalized_header,
                    finality_branch: finality_branch.into(),
                    sync_aggregate: sync_aggregate.clone(),
                    signature_slot: block_slot,
                })
            }
            ForkName::Deneb => {
                let attested_header =
                    LightClientHeaderDeneb::block_to_light_client_header(attested_block)?;

                let finalized_header = if let Some(finalized_block) = finalized_block {
                    LightClientHeaderDeneb::block_to_light_client_header(finalized_block)?
                } else {
                    LightClientHeaderDeneb::default()
                };

                Self::Deneb(LightClientUpdateDeneb {
                    attested_header,
                    next_sync_committee,
                    next_sync_committee_branch: next_sync_committee_branch.into(),
                    finalized_header,
                    finality_branch: finality_branch.into(),
                    sync_aggregate: sync_aggregate.clone(),
                    signature_slot: block_slot,
                })
            }
            ForkName::Electra => {
                let attested_header =
                    LightClientHeaderElectra::block_to_light_client_header(attested_block)?;

                let finalized_header = if let Some(finalized_block) = finalized_block {
                    LightClientHeaderElectra::block_to_light_client_header(finalized_block)?
                } else {
                    LightClientHeaderElectra::default()
                };

                Self::Electra(LightClientUpdateElectra {
                    attested_header,
                    next_sync_committee,
                    next_sync_committee_branch: next_sync_committee_branch.into(),
                    finalized_header,
                    finality_branch: finality_branch.into(),
                    sync_aggregate: sync_aggregate.clone(),
                    signature_slot: block_slot,
                })
            } // To add a new fork, just append the new fork variant on the latest fork. Forks that
              // have a distinct execution header will need a new LightClientUpdate variant only
              // if you need to test or support lightclient usages
        };

        Ok(light_client_update)
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: &ForkName) -> Result<Self, ssz::DecodeError> {
        let update = match fork_name {
            ForkName::Altair | ForkName::Bellatrix => {
                Self::Altair(LightClientUpdateAltair::from_ssz_bytes(bytes)?)
            }
            ForkName::Capella => Self::Capella(LightClientUpdateCapella::from_ssz_bytes(bytes)?),
            ForkName::Deneb => Self::Deneb(LightClientUpdateDeneb::from_ssz_bytes(bytes)?),
            ForkName::Electra => Self::Electra(LightClientUpdateElectra::from_ssz_bytes(bytes)?),
            ForkName::Base => {
                return Err(ssz::DecodeError::BytesInvalid(format!(
                    "LightClientUpdate decoding for {fork_name} not implemented"
                )))
            }
        };

        Ok(update)
    }

    pub fn attested_header_slot(&self) -> Slot {
        match self {
            LightClientUpdate::Altair(update) => update.attested_header.beacon.slot,
            LightClientUpdate::Capella(update) => update.attested_header.beacon.slot,
            LightClientUpdate::Deneb(update) => update.attested_header.beacon.slot,
            LightClientUpdate::Electra(update) => update.attested_header.beacon.slot,
        }
    }

    pub fn finalized_header_slot(&self) -> Slot {
        match self {
            LightClientUpdate::Altair(update) => update.finalized_header.beacon.slot,
            LightClientUpdate::Capella(update) => update.finalized_header.beacon.slot,
            LightClientUpdate::Deneb(update) => update.finalized_header.beacon.slot,
            LightClientUpdate::Electra(update) => update.finalized_header.beacon.slot,
        }
    }

    fn attested_header_sync_committee_period(
        &self,
        chain_spec: &ChainSpec,
    ) -> Result<Epoch, Error> {
        compute_sync_committee_period_at_slot::<E>(self.attested_header_slot(), chain_spec)
            .map_err(Error::ArithError)
    }

    fn signature_slot_sync_committee_period(&self, chain_spec: &ChainSpec) -> Result<Epoch, Error> {
        compute_sync_committee_period_at_slot::<E>(*self.signature_slot(), chain_spec)
            .map_err(Error::ArithError)
    }

    pub fn is_sync_committee_update(&self, chain_spec: &ChainSpec) -> Result<bool, Error> {
        Ok(!self.is_next_sync_committee_branch_empty()
            && (self.attested_header_sync_committee_period(chain_spec)?
                == self.signature_slot_sync_committee_period(chain_spec)?))
    }

    pub fn has_sync_committee_finality(&self, chain_spec: &ChainSpec) -> Result<bool, Error> {
        Ok(
            compute_sync_committee_period_at_slot::<E>(self.finalized_header_slot(), chain_spec)?
                == self.attested_header_sync_committee_period(chain_spec)?,
        )
    }

    // Implements spec prioritization rules:
    // Full nodes SHOULD provide the best derivable LightClientUpdate for each sync committee period
    // ref: https://github.com/ethereum/consensus-specs/blob/113c58f9bf9c08867f6f5f633c4d98e0364d612a/specs/altair/light-client/full-node.md#create_light_client_update
    pub fn is_better_light_client_update(
        &self,
        new: &Self,
        chain_spec: &ChainSpec,
    ) -> Result<bool, Error> {
        // Compare super majority (> 2/3) sync committee participation
        let max_active_participants = new.sync_aggregate().sync_committee_bits.len();

        let new_active_participants = new.sync_aggregate().sync_committee_bits.num_set_bits();
        let prev_active_participants = self.sync_aggregate().sync_committee_bits.num_set_bits();

        let new_has_super_majority =
            new_active_participants.safe_mul(3)? >= max_active_participants.safe_mul(2)?;
        let prev_has_super_majority =
            prev_active_participants.safe_mul(3)? >= max_active_participants.safe_mul(2)?;

        if new_has_super_majority != prev_has_super_majority {
            return Ok(new_has_super_majority);
        }

        if !new_has_super_majority && new_active_participants != prev_active_participants {
            return Ok(new_active_participants > prev_active_participants);
        }

        // Compare presence of relevant sync committee
        let new_has_relevant_sync_committee = new.is_sync_committee_update(chain_spec)?;
        let prev_has_relevant_sync_committee = self.is_sync_committee_update(chain_spec)?;
        if new_has_relevant_sync_committee != prev_has_relevant_sync_committee {
            return Ok(new_has_relevant_sync_committee);
        }

        // Compare indication of any finality
        let new_has_finality = !new.is_finality_branch_empty();
        let prev_has_finality = !self.is_finality_branch_empty();
        if new_has_finality != prev_has_finality {
            return Ok(new_has_finality);
        }

        // Compare sync committee finality
        if new_has_finality {
            let new_has_sync_committee_finality = new.has_sync_committee_finality(chain_spec)?;
            let prev_has_sync_committee_finality = self.has_sync_committee_finality(chain_spec)?;
            if new_has_sync_committee_finality != prev_has_sync_committee_finality {
                return Ok(new_has_sync_committee_finality);
            }
        }

        // Tiebreaker 1: Sync committee participation beyond super majority
        if new_active_participants != prev_active_participants {
            return Ok(new_active_participants > prev_active_participants);
        }

        let new_attested_header_slot = new.attested_header_slot();
        let prev_attested_header_slot = self.attested_header_slot();

        // Tiebreaker 2: Prefer older data (fewer changes to best)
        if new_attested_header_slot != prev_attested_header_slot {
            return Ok(new_attested_header_slot < prev_attested_header_slot);
        }

        Ok(new.signature_slot() < self.signature_slot())
    }

    fn is_next_sync_committee_branch_empty<'a>(&'a self) -> bool {
        map_light_client_update_ref!(&'a _, self.to_ref(), |update, cons| {
            cons(update);
            is_empty_branch(update.next_sync_committee_branch.as_ref())
        })
    }

    pub fn is_finality_branch_empty<'a>(&'a self) -> bool {
        map_light_client_update_ref!(&'a _, self.to_ref(), |update, cons| {
            cons(update);
            is_empty_branch(update.finality_branch.as_ref())
        })
    }

    // A `LightClientUpdate` has two `LightClientHeader`s
    // Spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#lightclientupdate
    #[allow(clippy::arithmetic_side_effects)]
    pub fn ssz_max_len_for_fork(fork_name: ForkName) -> usize {
        let fixed_len = match fork_name {
            ForkName::Base | ForkName::Bellatrix => 0,
            ForkName::Altair => <LightClientUpdateAltair<E> as Encode>::ssz_fixed_len(),
            ForkName::Capella => <LightClientUpdateCapella<E> as Encode>::ssz_fixed_len(),
            ForkName::Deneb => <LightClientUpdateDeneb<E> as Encode>::ssz_fixed_len(),
            ForkName::Electra => <LightClientUpdateElectra<E> as Encode>::ssz_fixed_len(),
        };
        fixed_len + 2 * LightClientHeader::<E>::ssz_max_var_len_for_fork(fork_name)
    }

    pub fn map_with_fork_name<F, R>(&self, func: F) -> R
    where
        F: Fn(ForkName) -> R,
    {
        match self {
            Self::Altair(_) => func(ForkName::Altair),
            Self::Capella(_) => func(ForkName::Capella),
            Self::Deneb(_) => func(ForkName::Deneb),
            Self::Electra(_) => func(ForkName::Electra),
        }
    }
}

fn is_empty_branch(branch: &[Hash256]) -> bool {
    for index in branch.iter() {
        if *index != Hash256::default() {
            return false;
        }
    }
    true
}

fn compute_sync_committee_period_at_slot<E: EthSpec>(
    slot: Slot,
    chain_spec: &ChainSpec,
) -> Result<Epoch, ArithError> {
    slot.epoch(E::slots_per_epoch())
        .safe_div(chain_spec.epochs_per_sync_committee_period)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz_types::typenum::Unsigned;

    // `ssz_tests!` can only be defined once per namespace
    #[cfg(test)]
    mod altair {
        use super::*;
        use crate::MainnetEthSpec;
        ssz_tests!(LightClientUpdateAltair<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod capella {
        use super::*;
        use crate::MainnetEthSpec;
        ssz_tests!(LightClientUpdateCapella<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod deneb {
        use super::*;
        use crate::MainnetEthSpec;
        ssz_tests!(LightClientUpdateDeneb<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod electra {
        use super::*;
        use crate::MainnetEthSpec;
        ssz_tests!(LightClientUpdateElectra<MainnetEthSpec>);
    }

    #[test]
    fn finalized_root_params() {
        assert!(2usize.pow(FINALIZED_ROOT_PROOF_LEN as u32) <= FINALIZED_ROOT_INDEX);
        assert!(2usize.pow(FINALIZED_ROOT_PROOF_LEN as u32 + 1) > FINALIZED_ROOT_INDEX);
        assert_eq!(FinalizedRootProofLen::to_usize(), FINALIZED_ROOT_PROOF_LEN);

        assert!(
            2usize.pow(FINALIZED_ROOT_PROOF_LEN_ELECTRA as u32) <= FINALIZED_ROOT_INDEX_ELECTRA
        );
        assert!(
            2usize.pow(FINALIZED_ROOT_PROOF_LEN_ELECTRA as u32 + 1) > FINALIZED_ROOT_INDEX_ELECTRA
        );
        assert_eq!(
            FinalizedRootProofLenElectra::to_usize(),
            FINALIZED_ROOT_PROOF_LEN_ELECTRA
        );
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

        assert!(
            2usize.pow(CURRENT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA as u32)
                <= CURRENT_SYNC_COMMITTEE_INDEX_ELECTRA
        );
        assert!(
            2usize.pow(CURRENT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA as u32 + 1)
                > CURRENT_SYNC_COMMITTEE_INDEX_ELECTRA
        );
        assert_eq!(
            CurrentSyncCommitteeProofLenElectra::to_usize(),
            CURRENT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA
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

        assert!(
            2usize.pow(NEXT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA as u32)
                <= NEXT_SYNC_COMMITTEE_INDEX_ELECTRA
        );
        assert!(
            2usize.pow(NEXT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA as u32 + 1)
                > NEXT_SYNC_COMMITTEE_INDEX_ELECTRA
        );
        assert_eq!(
            NextSyncCommitteeProofLenElectra::to_usize(),
            NEXT_SYNC_COMMITTEE_PROOF_LEN_ELECTRA
        );
    }
}
