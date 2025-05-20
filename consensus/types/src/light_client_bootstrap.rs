use crate::context_deserialize;
use crate::ForkVersionDecode;
use crate::{
    light_client_update::*, BeaconState, ChainSpec, ContextDeserialize, EthSpec, FixedVector,
    ForkName, Hash256, LightClientHeader, SignedBlindedBeaconBlock, Slot, SyncCommittee,
};
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{DecodeError, Encode};
use ssz_derive::Encode;
use std::sync::Arc;
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

/// A LightClientBootstrap is the initializer we send over to light_client nodes
/// that are trying to generate their basic storage when booting up.
#[superstruct(
    variants(Altair, Capella, Deneb, Electra, Fulu),
    variant_attributes(
        derive(
            Debug,
            Clone,
            PartialEq,
            Serialize,
            Deserialize,
            Derivative,
            Encode,
            arbitrary::Arbitrary,
            TreeHash,
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
        context_deserialize(ForkName),
    )
)]
#[derive(
    Debug, Clone, Serialize, TreeHash, Encode, Deserialize, arbitrary::Arbitrary, PartialEq,
)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[arbitrary(bound = "E: EthSpec")]
pub struct LightClientBootstrap<E: EthSpec> {
    /// The requested beacon block header.
    pub header: LightClientHeader<E>,
    /// The `SyncCommittee` used in the requested period.
    pub current_sync_committee: Arc<SyncCommittee<E>>,
    /// Merkle proof for sync committee
    #[superstruct(
        only(Altair, Capella, Deneb),
        partial_getter(rename = "current_sync_committee_branch_altair")
    )]
    pub current_sync_committee_branch: FixedVector<Hash256, CurrentSyncCommitteeProofLen>,
    #[superstruct(
        only(Electra, Fulu),
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
        }
    }

    pub fn get_slot<'a>(&'a self) -> Slot {
        map_light_client_bootstrap_ref!(&'a _, self.to_ref(), |inner, cons| {
            cons(inner);
            inner.header.beacon().slot
        })
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
        };
        fixed_len + LightClientHeader::<E>::ssz_max_var_len_for_fork(fork_name)
    }

    pub fn new(
        block: &SignedBlindedBeaconBlock<E>,
        current_sync_committee: Arc<SyncCommittee<E>>,
        current_sync_committee_branch: Vec<Hash256>,
        chain_spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let header = LightClientHeader::block_to_light_client_header(block, chain_spec)?;
        let light_client_bootstrap = match block
            .fork_name(chain_spec)
            .map_err(|_| Error::InconsistentFork)?
        {
            ForkName::Base => return Err(Error::AltairForkNotActive),
            ForkName::Altair | ForkName::Bellatrix => Self::Altair(LightClientBootstrapAltair {
                header,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Capella => Self::Capella(LightClientBootstrapCapella {
                header,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Deneb => Self::Deneb(LightClientBootstrapDeneb {
                header,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Electra => Self::Electra(LightClientBootstrapElectra {
                header,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Fulu => Self::Fulu(LightClientBootstrapFulu {
                header,
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
        let mut header = beacon_state.latest_block_header().clone();
        header.state_root = beacon_state.update_tree_hash_cache()?;
        let current_sync_committee_branch = beacon_state.compute_current_sync_committee_proof()?;
        let current_sync_committee = beacon_state.current_sync_committee()?.clone();

        let header = LightClientHeader::block_to_light_client_header(block, chain_spec)?;

        let light_client_bootstrap = match block
            .fork_name(chain_spec)
            .map_err(|_| Error::InconsistentFork)?
        {
            ForkName::Base => return Err(Error::AltairForkNotActive),
            ForkName::Altair | ForkName::Bellatrix => Self::Altair(LightClientBootstrapAltair {
                header,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Capella => Self::Capella(LightClientBootstrapCapella {
                header,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Deneb => Self::Deneb(LightClientBootstrapDeneb {
                header,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Electra => Self::Electra(LightClientBootstrapElectra {
                header,
                current_sync_committee,
                current_sync_committee_branch: current_sync_committee_branch.into(),
            }),
            ForkName::Fulu => Self::Fulu(LightClientBootstrapFulu {
                header,
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
                )))
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
        })
    }
}

impl<E: EthSpec> ForkVersionDecode for LightClientBootstrap<E> {
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        // header
        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<SyncCommittee<E>>()?;

        if fork_name.electra_enabled() {
            builder.register_type::<FixedVector<Hash256, CurrentSyncCommitteeProofLenElectra>>()?;
        } else {
            builder.register_type::<FixedVector<Hash256, CurrentSyncCommitteeProofLen>>()?;
        }
        let mut decoder = builder.build()?;
        let header = decoder.decode_next_with(|bytes| {
            LightClientHeader::from_ssz_bytes_by_fork(bytes, fork_name)
        })?;
        match fork_name {
            ForkName::Base => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for LightClientBootstrap: {fork_name}",
            ))),
            ForkName::Altair | ForkName::Bellatrix => {
                let current_sync_committee = decoder.decode_next()?;
                let current_sync_committee_branch = decoder.decode_next()?;
                Ok(Self::Altair(LightClientBootstrapAltair {
                    header,
                    current_sync_committee,
                    current_sync_committee_branch,
                }))
            }
            ForkName::Capella => {
                let current_sync_committee = decoder.decode_next()?;
                let current_sync_committee_branch = decoder.decode_next()?;
                Ok(Self::Capella(LightClientBootstrapCapella {
                    header,
                    current_sync_committee,
                    current_sync_committee_branch,
                }))
            }
            ForkName::Deneb => {
                let current_sync_committee = decoder.decode_next()?;
                let current_sync_committee_branch = decoder.decode_next()?;
                Ok(Self::Deneb(LightClientBootstrapDeneb {
                    header,
                    current_sync_committee,
                    current_sync_committee_branch,
                }))
            }
            ForkName::Electra => {
                let current_sync_committee = decoder.decode_next()?;
                let current_sync_committee_branch = decoder.decode_next()?;
                Ok(Self::Electra(LightClientBootstrapElectra {
                    header,
                    current_sync_committee,
                    current_sync_committee_branch,
                }))
            }
            ForkName::Fulu => {
                let current_sync_committee = decoder.decode_next()?;
                let current_sync_committee_branch = decoder.decode_next()?;
                Ok(Self::Fulu(LightClientBootstrapFulu {
                    header,
                    current_sync_committee,
                    current_sync_committee_branch,
                }))
            }
        }
    }
}
