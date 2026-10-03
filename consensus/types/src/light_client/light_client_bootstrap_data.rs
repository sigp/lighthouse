use std::sync::Arc;

use context_deserialize::{ContextDeserialize};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;
use typenum::U1;

use crate::{
    core::{EthSpec, Hash256},
    fork::ForkName,
    light_client::{
        CurrentSyncCommitteeProofLen, CurrentSyncCommitteeProofLenElectra, ExecutionPayloadProofLen,
        LightClientError,
    },
    sync_committee::SyncCommittee,
};

pub type CurrentSyncCommitteeBranch = FixedVector<Hash256, CurrentSyncCommitteeProofLen>;
pub type CurrentSyncCommitteeBranchElectra =
    FixedVector<Hash256, CurrentSyncCommitteeProofLenElectra>;
pub type ExecutionBranch = FixedVector<Hash256, ExecutionPayloadProofLen>;


/// The full `current_sync_committee` is only present for the last checkpoint in a
/// period, and only once the period is fully finalized; other checkpoints contain
/// only `current_sync_committee_branch`.
///
/// Only two variants exist because the sole fork-dependent field is the committee
/// branch length (5 pre-Electra, 6 from Electra); `Altair` covers
/// Altair/Bellatrix/Capella/Deneb and `Electra` covers Electra/Fulu, mirroring how
/// `LightClientBootstrap` groups branch lengths.
#[superstruct(
    variants(Altair, Electra),
    variant_attributes(
        derive(Debug, Clone, Serialize, Deserialize, Educe, Decode, Encode, TreeHash),
        educe(PartialEq),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec")
        ),
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct LightClientBootstrapData<E: EthSpec> {
    /// `List[SyncCommittee, 1]`: empty unless this is the last checkpoint of a
    /// fully finalized period.
    pub current_sync_committee: VariableList<Arc<SyncCommittee<E>>, U1>,
    /// Merkle proof for the state's `current_sync_committee`.
    #[superstruct(only(Altair), partial_getter(rename = "current_sync_committee_branch_altair"))]
    pub current_sync_committee_branch: CurrentSyncCommitteeBranch,
    /// Merkle proof for the state's `current_sync_committee`.
    #[superstruct(only(Electra), partial_getter(rename = "current_sync_committee_branch_electra"))]
    pub current_sync_committee_branch: CurrentSyncCommitteeBranchElectra,
    /// `execution` header's block hash (pre-Gloas).
    pub execution_block_hash: Hash256,
    /// Merkle proof for the execution payload in `BeaconBlockBody`.
    pub execution_branch: ExecutionBranch,
}

impl<E: EthSpec> LightClientBootstrapData<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        current_sync_committee: VariableList<Arc<SyncCommittee<E>>, U1>,
        current_sync_committee_branch: Vec<Hash256>,
        execution_block_hash: Hash256,
        execution_branch: Vec<Hash256>,
        fork_name: ForkName,
    ) -> Result<Self, LightClientError> {
        match fork_name {
            ForkName::Base => Err(LightClientError::AltairForkNotActive),
            ForkName::Altair | ForkName::Bellatrix | ForkName::Capella | ForkName::Deneb => {
                Ok(Self::Altair(LightClientBootstrapDataAltair {
                    current_sync_committee,
                    current_sync_committee_branch: current_sync_committee_branch
                        .try_into()
                        .map_err(LightClientError::SszTypesError)?,
                    execution_block_hash,
                    execution_branch: execution_branch
                        .try_into()
                        .map_err(LightClientError::SszTypesError)?,
                }))
            }
            ForkName::Electra | ForkName::Fulu => Ok(Self::Electra(LightClientBootstrapDataElectra {
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch
                    .try_into()
                    .map_err(LightClientError::SszTypesError)?,
                execution_block_hash,
                execution_branch: execution_branch
                    .try_into()
                    .map_err(LightClientError::SszTypesError)?,
            })),
            // TODO(gloas): progressive containers change all generalized indices.
            ForkName::Gloas => Err(LightClientError::GloasNotImplemented),
            ForkName::Heze => Err(LightClientError::HezeNotImplemented),
        }
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Altair | ForkName::Bellatrix | ForkName::Capella | ForkName::Deneb => {
                Ok(Self::Altair(LightClientBootstrapDataAltair::from_ssz_bytes(bytes)?))
            }
            ForkName::Electra | ForkName::Fulu => {
                Ok(Self::Electra(LightClientBootstrapDataElectra::from_ssz_bytes(bytes)?))
            }
            ForkName::Base | ForkName::Gloas | ForkName::Heze => {
                Err(ssz::DecodeError::BytesInvalid(format!(
                    "LightClientBootstrapData decoding for {fork_name} not implemented"
                )))
            }
        }
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for LightClientBootstrapData<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "LightClientBootstrapData failed to deserialize: {:?}",
                e
            ))
        };
        Ok(match context {
            ForkName::Altair | ForkName::Bellatrix | ForkName::Capella | ForkName::Deneb => {
                Self::Altair(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Electra | ForkName::Fulu => {
                Self::Electra(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Base | ForkName::Gloas | ForkName::Heze => {
                return Err(serde::de::Error::custom(format!(
                    "LightClientBootstrapData failed to deserialize: unsupported fork '{context}'"
                )))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    // `ssz_tests!` can only be defined once per namespace
    #[cfg(test)]
    mod altair {
        use crate::{light_client::light_client_bootstrap_data::LightClientBootstrapDataAltair, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapDataAltair<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod electra {
        use crate::{light_client::light_client_bootstrap_data::LightClientBootstrapDataElectra, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapDataElectra<MainnetEthSpec>);
    }
}