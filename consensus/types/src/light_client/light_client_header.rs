use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    block::{BeaconBlockBody, BeaconBlockHeader, SignedBlindedBeaconBlock},
    core::{ChainSpec, Hash256},
    execution::{
        ExecutionPayloadHeader, ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb,
        ExecutionPayloadHeaderElectra, ExecutionPayloadHeaderFulu,
    },
    fork::ForkName,
    light_client::{ExecutionPayloadProofLen, LightClientError, consts::EXECUTION_PAYLOAD_INDEX},
};

#[superstruct(
    variants(Altair, Capella, Deneb, Electra, Fulu,),
    variant_attributes(
        derive(Debug, Clone, Serialize, Deserialize, Educe, Decode, Encode, TreeHash,),
        educe(PartialEq),
        serde(deny_unknown_fields),
        cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary),),
        context_deserialize(ForkName),
    )
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, TreeHash, Encode, PartialEq)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(deny_unknown_fields)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,

    #[superstruct(
        only(Capella),
        partial_getter(rename = "execution_payload_header_capella")
    )]
    pub execution: ExecutionPayloadHeaderCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_header_deneb"))]
    pub execution: ExecutionPayloadHeaderDeneb,
    #[superstruct(
        only(Electra),
        partial_getter(rename = "execution_payload_header_electra")
    )]
    pub execution: ExecutionPayloadHeaderElectra,
    #[superstruct(only(Fulu), partial_getter(rename = "execution_payload_header_fulu"))]
    pub execution: ExecutionPayloadHeaderFulu,

    #[superstruct(only(Capella, Deneb, Electra, Fulu))]
    pub execution_branch: FixedVector<Hash256, ExecutionPayloadProofLen>,
}

impl LightClientHeader {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock,
        chain_spec: &ChainSpec,
    ) -> Result<Self, LightClientError> {
        let header = match block
            .fork_name(chain_spec)
            .map_err(|_| LightClientError::InconsistentFork)?
        {
            ForkName::Base => return Err(LightClientError::AltairForkNotActive),
            ForkName::Altair | ForkName::Bellatrix => LightClientHeader::Altair(
                LightClientHeaderAltair::block_to_light_client_header(block)?,
            ),
            ForkName::Capella => LightClientHeader::Capella(
                LightClientHeaderCapella::block_to_light_client_header(block)?,
            ),
            ForkName::Deneb => LightClientHeader::Deneb(
                LightClientHeaderDeneb::block_to_light_client_header(block)?,
            ),
            ForkName::Electra => LightClientHeader::Electra(
                LightClientHeaderElectra::block_to_light_client_header(block)?,
            ),
            ForkName::Fulu => {
                LightClientHeader::Fulu(LightClientHeaderFulu::block_to_light_client_header(block)?)
            }
            // TODO(gloas): implement Gloas light client
            ForkName::Gloas => return Err(LightClientError::GloasNotImplemented),
            ForkName::Heze => return Err(LightClientError::HezeNotImplemented),
        };
        Ok(header)
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let header = match fork_name {
            ForkName::Altair | ForkName::Bellatrix => {
                LightClientHeader::Altair(LightClientHeaderAltair::from_ssz_bytes(bytes)?)
            }
            ForkName::Capella => {
                LightClientHeader::Capella(LightClientHeaderCapella::from_ssz_bytes(bytes)?)
            }
            ForkName::Deneb => {
                LightClientHeader::Deneb(LightClientHeaderDeneb::from_ssz_bytes(bytes)?)
            }
            ForkName::Electra => {
                LightClientHeader::Electra(LightClientHeaderElectra::from_ssz_bytes(bytes)?)
            }
            ForkName::Fulu => {
                LightClientHeader::Fulu(LightClientHeaderFulu::from_ssz_bytes(bytes)?)
            }
            // TODO(gloas): implement Gloas light client
            ForkName::Base | ForkName::Gloas | ForkName::Heze => {
                return Err(ssz::DecodeError::BytesInvalid(format!(
                    "LightClientHeader decoding for {fork_name} not implemented"
                )));
            }
        };

        Ok(header)
    }

    /// Custom SSZ decoder that takes a `ForkName` as context.
    pub fn from_ssz_bytes_for_fork(
        bytes: &[u8],
        fork_name: ForkName,
    ) -> Result<Self, ssz::DecodeError> {
        Self::from_ssz_bytes(bytes, fork_name)
    }

    pub fn ssz_max_var_len_for_fork(fork_name: ForkName) -> usize {
        if fork_name.gloas_enabled() {
            // TODO(EIP7732): check this
            0
        } else if fork_name.capella_enabled() {
            ExecutionPayloadHeader::ssz_max_var_len_for_fork(fork_name)
        } else {
            0
        }
    }
}

impl LightClientHeaderAltair {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock,
    ) -> Result<Self, LightClientError> {
        Ok(LightClientHeaderAltair {
            beacon: block.message().block_header(),
        })
    }
}

impl Default for LightClientHeaderAltair {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
        }
    }
}

impl LightClientHeaderCapella {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock,
    ) -> Result<Self, LightClientError> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_capella()?;

        let header = ExecutionPayloadHeaderCapella::from(payload);
        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_capella()
                .map_err(|_| LightClientError::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderCapella {
            beacon: block.message().block_header(),
            execution: header,
            execution_branch: FixedVector::new(execution_branch)?,
        })
    }
}

impl Default for LightClientHeaderCapella {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeaderCapella::default(),
            execution_branch: FixedVector::default(),
        }
    }
}

impl LightClientHeaderDeneb {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock,
    ) -> Result<Self, LightClientError> {
        let header = block
            .message()
            .execution_payload()?
            .execution_payload_deneb()?
            .clone();

        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_deneb()
                .map_err(|_| LightClientError::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderDeneb {
            beacon: block.message().block_header(),
            execution: header,
            execution_branch: FixedVector::new(execution_branch)?,
        })
    }
}

impl Default for LightClientHeaderDeneb {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeaderDeneb::default(),
            execution_branch: FixedVector::default(),
        }
    }
}

impl LightClientHeaderElectra {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock,
    ) -> Result<Self, LightClientError> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_electra()?;

        let header = ExecutionPayloadHeaderElectra::from(payload);
        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_electra()
                .map_err(|_| LightClientError::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderElectra {
            beacon: block.message().block_header(),
            execution: header,
            execution_branch: FixedVector::new(execution_branch)?,
        })
    }
}

impl Default for LightClientHeaderElectra {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeaderElectra::default(),
            execution_branch: FixedVector::default(),
        }
    }
}

impl LightClientHeaderFulu {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock,
    ) -> Result<Self, LightClientError> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_fulu()?;

        let header = ExecutionPayloadHeaderFulu::from(payload);
        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_fulu()
                .map_err(|_| LightClientError::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderFulu {
            beacon: block.message().block_header(),
            execution: header,
            execution_branch: FixedVector::new(execution_branch)?,
        })
    }
}

impl Default for LightClientHeaderFulu {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeaderFulu::default(),
            execution_branch: FixedVector::default(),
        }
    }
}

impl<'de> ContextDeserialize<'de, ForkName> for LightClientHeader {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "LightClientFinalityUpdate failed to deserialize: {:?}",
                e
            ))
        };
        Ok(match context {
            // TODO(gloas): implement Gloas light client
            ForkName::Base | ForkName::Gloas | ForkName::Heze => {
                return Err(serde::de::Error::custom(format!(
                    "LightClientFinalityUpdate failed to deserialize: unsupported fork '{}'",
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
        })
    }
}

#[cfg(test)]
mod tests {
    // `ssz_tests!` can only be defined once per namespace
    #[cfg(test)]
    mod altair {
        use crate::LightClientHeaderAltair;
        ssz_tests!(LightClientHeaderAltair);
    }

    #[cfg(test)]
    mod capella {
        use crate::LightClientHeaderCapella;
        ssz_tests!(LightClientHeaderCapella);
    }

    #[cfg(test)]
    mod deneb {
        use crate::LightClientHeaderDeneb;
        ssz_tests!(LightClientHeaderDeneb);
    }

    #[cfg(test)]
    mod electra {
        use crate::LightClientHeaderElectra;
        ssz_tests!(LightClientHeaderElectra);
    }

    #[cfg(test)]
    mod fulu {
        use crate::LightClientHeaderFulu;
        ssz_tests!(LightClientHeaderFulu);
    }
}
