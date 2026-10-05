use std::sync::Arc;

use context_deserialize::ContextDeserialize;
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
        CurrentSyncCommitteeProofLen, CurrentSyncCommitteeProofLenElectra,
        ExecutionPayloadProofLen, LightClientError,
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
#[superstruct(
    variants(Altair, Capella, Deneb, Electra, Fulu),
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
    #[superstruct(
        only(Altair, Capella, Deneb),
        partial_getter(rename = "current_sync_committee_branch_altair")
    )]
    pub current_sync_committee_branch: CurrentSyncCommitteeBranch,
    /// Merkle proof for the state's `current_sync_committee`.
    #[superstruct(
        only(Electra, Fulu),
        partial_getter(rename = "current_sync_committee_branch_electra")
    )]
    pub current_sync_committee_branch: CurrentSyncCommitteeBranchElectra,
    /// `execution` header's block hash (pre-Gloas). Absent for Altair/Bellatrix, which
    /// use the Altair-era light client header with no execution fields.
    #[superstruct(only(Capella, Deneb, Electra, Fulu))]
    pub execution_block_hash: Hash256,
    /// Merkle proof for the execution payload in `BeaconBlockBody`. Absent for
    /// Altair/Bellatrix, same reason as `execution_block_hash`.
    #[superstruct(only(Capella, Deneb, Electra, Fulu))]
    pub execution_branch: ExecutionBranch,
}

impl<E: EthSpec> LightClientBootstrapData<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        current_sync_committee: VariableList<Arc<SyncCommittee<E>>, U1>,
        current_sync_committee_branch: Vec<Hash256>,
        execution: Option<(Hash256, Vec<Hash256>)>,
        fork_name: ForkName,
    ) -> Result<Self, LightClientError> {
        match fork_name {
            ForkName::Base => Err(LightClientError::AltairForkNotActive),
            ForkName::Altair | ForkName::Bellatrix => {
                if execution.is_some() {
                    return Err(LightClientError::InconsistentFork);
                }
                Ok(Self::Altair(LightClientBootstrapDataAltair {
                    current_sync_committee,
                    current_sync_committee_branch: current_sync_committee_branch
                        .try_into()
                        .map_err(LightClientError::SszTypesError)?,
                }))
            }
            ForkName::Capella => {
                let (execution_block_hash, execution_branch) =
                    execution.ok_or(LightClientError::InconsistentFork)?;
                Ok(Self::Capella(LightClientBootstrapDataCapella {
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
            ForkName::Deneb => {
                let (execution_block_hash, execution_branch) =
                    execution.ok_or(LightClientError::InconsistentFork)?;
                Ok(Self::Deneb(LightClientBootstrapDataDeneb {
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
            ForkName::Electra => {
                let (execution_block_hash, execution_branch) =
                    execution.ok_or(LightClientError::InconsistentFork)?;
                Ok(Self::Electra(LightClientBootstrapDataElectra {
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
            ForkName::Fulu => {
                let (execution_block_hash, execution_branch) =
                    execution.ok_or(LightClientError::InconsistentFork)?;
                Ok(Self::Fulu(LightClientBootstrapDataFulu {
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
            // TODO(gloas): progressive containers change all generalized indices.
            ForkName::Gloas => Err(LightClientError::GloasNotImplemented),
            ForkName::Heze => Err(LightClientError::HezeNotImplemented),
        }
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Altair | ForkName::Bellatrix => {
                Ok(Self::Altair(LightClientBootstrapDataAltair::from_ssz_bytes(bytes)?))
            }
            ForkName::Capella => {
                Ok(Self::Capella(LightClientBootstrapDataCapella::from_ssz_bytes(bytes)?))
            }
            ForkName::Deneb => {
                Ok(Self::Deneb(LightClientBootstrapDataDeneb::from_ssz_bytes(bytes)?))
            }
            ForkName::Electra => {
                Ok(Self::Electra(LightClientBootstrapDataElectra::from_ssz_bytes(bytes)?))
            }
            ForkName::Fulu => {
                Ok(Self::Fulu(LightClientBootstrapDataFulu::from_ssz_bytes(bytes)?))
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
            ForkName::Altair | ForkName::Bellatrix => {
                Self::Altair(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Capella => {
                Self::Capella(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Deneb => {
                Self::Deneb(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Electra => {
                Self::Electra(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Fulu => {
                Self::Fulu(Deserialize::deserialize(deserializer).map_err(convert_err)?)
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
    use super::*;
    use crate::MainnetEthSpec;

    // `ssz_tests!` can only be defined once per namespace
    #[cfg(test)]
    mod altair {
        use crate::{light_client::light_client_bootstrap_data::LightClientBootstrapDataAltair, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapDataAltair<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod capella {
        use crate::{light_client::light_client_bootstrap_data::LightClientBootstrapDataCapella, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapDataCapella<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod deneb {
        use crate::{light_client::light_client_bootstrap_data::LightClientBootstrapDataDeneb, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapDataDeneb<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod electra {
        use crate::{light_client::light_client_bootstrap_data::LightClientBootstrapDataElectra, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapDataElectra<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod fulu {
        use crate::{light_client::light_client_bootstrap_data::LightClientBootstrapDataFulu, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapDataFulu<MainnetEthSpec>);
    }

    /// Confirms `new()` actually rejects a fork/execution-option mismatch instead of
    /// silently dropping data
    #[test]
    fn new_rejects_execution_data_for_altair_and_bellatrix() {
        for fork_name in [ForkName::Altair, ForkName::Bellatrix] {
            let err = LightClientBootstrapData::<MainnetEthSpec>::new(
                VariableList::empty(),
                vec![Hash256::repeat_byte(0); 5],
                Some((Hash256::repeat_byte(0), vec![Hash256::repeat_byte(0); 4])),
                fork_name,
            )
            .unwrap_err();
            assert_eq!(err, LightClientError::InconsistentFork);
        }
    }

    /// Confirms `new()` rejects a missing execution payload from Capella onward,
    /// rather than defaulting it to zeroes.
    #[test]
    fn new_rejects_missing_execution_data_from_capella_onward() {
        for fork_name in [
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
        ] {
            let branch_len = if fork_name.electra_enabled() { 6 } else { 5 };
            let err = LightClientBootstrapData::<MainnetEthSpec>::new(
                VariableList::empty(),
                vec![Hash256::repeat_byte(0); branch_len],
                None,
                fork_name,
            )
            .unwrap_err();
            assert_eq!(err, LightClientError::InconsistentFork);
        }
    }

    #[test]
    fn new_dispatches_altair_and_bellatrix_to_altair_variant() {
        for fork_name in [ForkName::Altair, ForkName::Bellatrix] {
            let data = LightClientBootstrapData::<MainnetEthSpec>::new(
                VariableList::empty(),
                vec![Hash256::repeat_byte(0); 5],
                None,
                fork_name,
            )
            .unwrap();
            assert!(matches!(data, LightClientBootstrapData::Altair(_)));
        }
    }

    #[test]
    fn new_dispatches_capella_through_fulu_with_execution_data() {
        for fork_name in [
            ForkName::Capella,
            ForkName::Deneb,
            ForkName::Electra,
            ForkName::Fulu,
        ] {
            let branch_len = if fork_name.electra_enabled() { 6 } else { 5 };
            let data = LightClientBootstrapData::<MainnetEthSpec>::new(
                VariableList::empty(),
                vec![Hash256::repeat_byte(0); branch_len],
                Some((Hash256::repeat_byte(0), vec![Hash256::repeat_byte(0); 4])),
                fork_name,
            )
            .unwrap();
            match fork_name {
                ForkName::Capella => assert!(matches!(data, LightClientBootstrapData::Capella(_))),
                ForkName::Deneb => assert!(matches!(data, LightClientBootstrapData::Deneb(_))),
                ForkName::Electra => assert!(matches!(data, LightClientBootstrapData::Electra(_))),
                ForkName::Fulu => assert!(matches!(data, LightClientBootstrapData::Fulu(_))),
                _ => unreachable!(),
            }
        }
    }
}