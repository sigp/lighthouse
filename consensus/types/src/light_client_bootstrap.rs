use crate::context_deserialize;
use crate::{
    BeaconState, ChainSpec, ContextDeserialize, EthSpec, FixedVector, ForkName, Hash256,
    LightClientHeader, LightClientHeaderAltair, LightClientHeaderCapella, LightClientHeaderDeneb,
    LightClientHeaderElectra, LightClientHeaderFulu, LightClientHeaderGloas,
    SignedBlindedBeaconBlock, Slot, SyncCommittee, light_client_update::*, test_utils::TestRandom,
};
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// A LightClientBootstrap is the initializer we send over to light_client nodes
/// that are trying to generate their basic storage when booting up.
#[superstruct(
    variants(Altair, Capella, Deneb, Electra, Fulu, Gloas),
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
            TreeHash,
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
        context_deserialize(ForkName),
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, TreeHash, Encode, Deserialize, PartialEq)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct LightClientBootstrap<E: EthSpec> {
    /// The requested beacon block header.
    #[superstruct(only(Altair), partial_getter(rename = "header_altair"))]
    pub header: LightClientHeaderAltair<E>,
    #[superstruct(only(Capella), partial_getter(rename = "header_capella"))]
    pub header: LightClientHeaderCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "header_deneb"))]
    pub header: LightClientHeaderDeneb<E>,
    #[superstruct(only(Electra), partial_getter(rename = "header_electra"))]
    pub header: LightClientHeaderElectra<E>,
    #[superstruct(only(Fulu), partial_getter(rename = "header_fulu"))]
    pub header: LightClientHeaderFulu<E>,
    #[superstruct(only(Gloas), partial_getter(rename = "header_gloas"))]
    pub header: LightClientHeaderGloas<E>,
    /// The `SyncCommittee` used in the requested period.
    pub current_sync_committee: Arc<SyncCommittee<E>>,
    /// Merkle proof for sync committee
    #[superstruct(
        only(Altair, Capella, Deneb),
        partial_getter(rename = "current_sync_committee_branch_altair")
    )]
    pub current_sync_committee_branch: FixedVector<Hash256, CurrentSyncCommitteeProofLen>,
    #[superstruct(
        only(Electra, Fulu, Gloas),
        partial_getter(rename = "current_sync_committee_branch_electra")
    )]
    pub current_sync_committee_branch: FixedVector<Hash256, CurrentSyncCommitteeProofLenElectra>,
}

impl<E: EthSpec> LightClientBootstrap<E> {
    pub fn map_with_fork_name<F, R>(&self, func: F) -> R
    where
        F: Fn(ForkName) -> R,
    {
        match self {
            Self::Altair(_) => func(ForkName::Altair),
            Self::Capella(_) => func(ForkName::Capella),
            Self::Deneb(_) => func(ForkName::Deneb),
            Self::Electra(_) => func(ForkName::Electra),
            Self::Fulu(_) => func(ForkName::Fulu),
            Self::Gloas(_) => func(ForkName::Gloas),
        }
    }

    pub fn get_slot<'a>(&'a self) -> Slot {
        map_light_client_bootstrap_ref!(&'a _, self.to_ref(), |inner, cons| {
            cons(inner);
            inner.header.beacon.slot
        })
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let bootstrap = match fork_name {
            ForkName::Altair | ForkName::Bellatrix => {
                Self::Altair(LightClientBootstrapAltair::from_ssz_bytes(bytes)?)
            }
            ForkName::Capella => Self::Capella(LightClientBootstrapCapella::from_ssz_bytes(bytes)?),
            ForkName::Deneb => Self::Deneb(LightClientBootstrapDeneb::from_ssz_bytes(bytes)?),
            ForkName::Electra => Self::Electra(LightClientBootstrapElectra::from_ssz_bytes(bytes)?),
            ForkName::Fulu => Self::Fulu(LightClientBootstrapFulu::from_ssz_bytes(bytes)?),
            ForkName::Gloas => Self::Gloas(LightClientBootstrapGloas::from_ssz_bytes(bytes)?),
            ForkName::Base => {
                return Err(ssz::DecodeError::BytesInvalid(format!(
                    "LightClientBootstrap decoding for {fork_name} not implemented"
                )));
            }
        };

        Ok(bootstrap)
    }

    #[allow(clippy::arithmetic_side_effects)]
    pub fn ssz_max_len_for_fork(fork_name: ForkName) -> usize {
        let fixed_len = match fork_name {
            ForkName::Base => 0,
            ForkName::Altair | ForkName::Bellatrix => {
                <LightClientBootstrapAltair<E> as Encode>::ssz_fixed_len()
            }
            ForkName::Capella => <LightClientBootstrapCapella<E> as Encode>::ssz_fixed_len(),
            ForkName::Deneb => <LightClientBootstrapDeneb<E> as Encode>::ssz_fixed_len(),
            ForkName::Electra => <LightClientBootstrapElectra<E> as Encode>::ssz_fixed_len(),
            ForkName::Fulu => <LightClientBootstrapFulu<E> as Encode>::ssz_fixed_len(),
            ForkName::Gloas => <LightClientBootstrapGloas<E> as Encode>::ssz_fixed_len(),
        };
        fixed_len + LightClientHeader::<E>::ssz_max_var_len_for_fork(fork_name)
    }

    pub fn new(
        block: &SignedBlindedBeaconBlock<E>,
        current_sync_committee: Arc<SyncCommittee<E>>,
        current_sync_committee_branch: Vec<Hash256>,
        chain_spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let light_client_bootstrap = match block
            .fork_name(chain_spec)
            .map_err(|_| Error::InconsistentFork)?
        {
            ForkName::Base => return Err(Error::AltairForkNotActive),
            ForkName::Altair | ForkName::Bellatrix => Self::Altair(LightClientBootstrapAltair {
                header: LightClientHeaderAltair::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Capella => Self::Capella(LightClientBootstrapCapella {
                header: LightClientHeaderCapella::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Deneb => Self::Deneb(LightClientBootstrapDeneb {
                header: LightClientHeaderDeneb::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Electra => Self::Electra(LightClientBootstrapElectra {
                header: LightClientHeaderElectra::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Fulu => Self::Fulu(LightClientBootstrapFulu {
                header: LightClientHeaderFulu::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Gloas => Self::Gloas(LightClientBootstrapGloas {
                header: LightClientHeaderGloas::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
        };

        Ok(light_client_bootstrap)
    }

    pub fn from_beacon_state(
        beacon_state: &mut BeaconState<E>,
        block: &SignedBlindedBeaconBlock<E>,
        chain_spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let current_sync_committee_branch = beacon_state.compute_current_sync_committee_proof()?;
        let current_sync_committee = beacon_state.current_sync_committee()?.clone();

        let light_client_bootstrap = match block
            .fork_name(chain_spec)
            .map_err(|_| Error::InconsistentFork)?
        {
            ForkName::Base => return Err(Error::AltairForkNotActive),
            ForkName::Altair | ForkName::Bellatrix => Self::Altair(LightClientBootstrapAltair {
                header: LightClientHeaderAltair::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Capella => Self::Capella(LightClientBootstrapCapella {
                header: LightClientHeaderCapella::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Deneb => Self::Deneb(LightClientBootstrapDeneb {
                header: LightClientHeaderDeneb::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Electra => Self::Electra(LightClientBootstrapElectra {
                header: LightClientHeaderElectra::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Fulu => Self::Fulu(LightClientBootstrapFulu {
                header: LightClientHeaderFulu::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Gloas => Self::Gloas(LightClientBootstrapGloas {
                header: LightClientHeaderGloas::block_to_light_client_header(block)?,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
        };

        Ok(light_client_bootstrap)
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for LightClientBootstrap<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "LightClientBootstrap failed to deserialize: {:?}",
                e
            ))
        };
        Ok(match context {
            ForkName::Base => {
                return Err(serde::de::Error::custom(format!(
                    "LightClientBootstrap failed to deserialize: unsupported fork '{}'",
                    context
                )));
            }
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
            ForkName::Gloas => {
                Self::Gloas(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    // `ssz_tests!` can only be defined once per namespace
    #[cfg(test)]
    mod altair {
        use crate::{LightClientBootstrapAltair, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapAltair<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod capella {
        use crate::{LightClientBootstrapCapella, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapCapella<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod deneb {
        use crate::{LightClientBootstrapDeneb, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapDeneb<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod electra {
        use crate::{LightClientBootstrapElectra, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapElectra<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod fulu {
        use crate::{LightClientBootstrapFulu, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapFulu<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod gloas {
        use crate::{LightClientBootstrapGloas, MainnetEthSpec};
        ssz_tests!(LightClientBootstrapGloas<MainnetEthSpec>);
    }
}
