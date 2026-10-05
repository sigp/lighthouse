use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    Hash256, block::BeaconBlockHeader, Checkpoint, core::{Epoch, EthSpec}, fork::ForkName, light_client::{
        light_client_bootstrap_data::LightClientBootstrapData, light_client_block_data::LightClientBlockData, FinalizedRootProofLen, FinalizedRootProofLenElectra, LightClientError,
    },
};

pub type FinalizedCheckpointBranch = FixedVector<Hash256, FinalizedRootProofLen>;
pub type FinalizedCheckpointBranchElectra = FixedVector<Hash256, FinalizedRootProofLenElectra>;

/// `LightClientEpochData` is data needed to advance a
/// `LightClientStore` by one epoch while verifying every field.
/// Only two variants exist; `Altair` covers
/// Altair/Bellatrix/Capella/Deneb and `Electra` covers Electra/Fulu.
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
#[derive(Debug, Clone, Serialize, Encode, Decode, TreeHash, PartialEq)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct LightClientEpochData<E: EthSpec> {
    /// The epoch this data advances the store through.
    pub epoch: Epoch,
    /// If `epoch > ALTAIR_FORK_EPOCH`: latest block at the start slot of `epoch - 1`
    /// (possibly from an even earlier epoch if that slot was missed).
    /// If `epoch == ALTAIR_FORK_EPOCH and ALTAIR_FORK_EPOCH > GENESIS_EPOCH`: latest
    /// block at the end of the previous epoch. Otherwise, default initialized.
    pub parent_block_header: BeaconBlockHeader,
    /// Per-slot data for the most recent `SLOTS_PER_EPOCH` slots. Empty slots are
    /// `default(LightClientBlockData)`.
    pub block_data: FixedVector<LightClientBlockData<E>, E::SlotsPerEpoch>,
    /// Bootstrap data for the checkpoint block (last non-empty `block_data[i]).
    pub bootstrap_data: LightClientBootstrapData<E>,
    /// For the first block within `epoch - 1` among `parent_block_header` and
    /// `block_data`, the corresponding `finalized_checkpoint`. Default initialized
    /// otherwise, or if no candidate block exists.
    pub finalized_checkpoint: Checkpoint,
    /// `floorlog2(get_generalized_index(BeaconState, "finalized_checkpoint"))`.
    #[superstruct(only(Altair), partial_getter(rename = "finalized_checkpoint_branch_altair"))]
    pub finalized_checkpoint_branch: FinalizedCheckpointBranch,
    /// `floorlog2(get_generalized_index(BeaconState, "finalized_checkpoint"))`.
    #[superstruct(only(Electra), partial_getter(rename = "finalized_checkpoint_branch_electra"))]
    pub finalized_checkpoint_branch: FinalizedCheckpointBranchElectra,
}

impl<E: EthSpec> LightClientEpochData<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: Epoch,
        parent_block_header: BeaconBlockHeader,
        block_data: FixedVector<LightClientBlockData<E>, E::SlotsPerEpoch>,
        bootstrap_data: LightClientBootstrapData<E>,
        finalized_checkpoint: Checkpoint,
        finalized_checkpoint_branch: Vec<Hash256>,
        fork_name: ForkName,
    ) -> Result<Self, LightClientError> {
        match fork_name {
            ForkName::Base => Err(LightClientError::AltairForkNotActive),
            ForkName::Altair | ForkName::Bellatrix | ForkName::Capella | ForkName::Deneb => {
                Ok(Self::Altair(LightClientEpochDataAltair {
                    epoch,
                    parent_block_header,
                    block_data,
                    bootstrap_data,
                    finalized_checkpoint,
                    finalized_checkpoint_branch: finalized_checkpoint_branch
                        .try_into()
                        .map_err(LightClientError::SszTypesError)?,
                }))
            }
            ForkName::Electra | ForkName::Fulu => Ok(Self::Electra(LightClientEpochDataElectra {
                epoch,
                parent_block_header,
                block_data,
                bootstrap_data,
                finalized_checkpoint,
                finalized_checkpoint_branch: finalized_checkpoint_branch
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
                Ok(Self::Altair(LightClientEpochDataAltair::from_ssz_bytes(bytes)?))
            }
            ForkName::Electra | ForkName::Fulu => {
                Ok(Self::Electra(LightClientEpochDataElectra::from_ssz_bytes(bytes)?))
            }
            ForkName::Base | ForkName::Gloas | ForkName::Heze => {
                Err(ssz::DecodeError::BytesInvalid(format!(
                    "LightClientEpochData decoding for {fork_name} not implemented"
                )))
            }
        }
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for LightClientEpochData<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "LightClientEpochData failed to deserialize: {:?}",
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
                    "LightClientEpochData failed to deserialize: unsupported fork '{context}'"
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
        use crate::{light_client::light_client_epoch_data::LightClientEpochDataAltair, MainnetEthSpec};
        ssz_tests!(LightClientEpochDataAltair<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod electra {
        use crate::{light_client::light_client_epoch_data::LightClientEpochDataElectra, MainnetEthSpec};
        ssz_tests!(LightClientEpochDataElectra<MainnetEthSpec>);
    }
}