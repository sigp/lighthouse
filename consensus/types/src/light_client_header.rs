use crate::ChainSpec;
use crate::context_deserialize;
use crate::{BeaconBlockBody, light_client_update::*};
use crate::{BeaconBlockHeader, ExecutionPayloadHeader};
use crate::{ContextDeserialize, ForkName};
use crate::{
    EthSpec, ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb,
    ExecutionPayloadHeaderElectra, ExecutionPayloadHeaderFulu, ExecutionPayloadHeaderGloas,
    FixedVector, Hash256, SignedBlindedBeaconBlock, test_utils::TestRandom,
};
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

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
#[derive(Debug, Clone, Serialize, TreeHash, Encode, PartialEq)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct LightClientHeader<E: EthSpec> {
    pub beacon: BeaconBlockHeader,

    #[superstruct(
        only(Capella),
        partial_getter(rename = "execution_payload_header_capella")
    )]
    pub execution: ExecutionPayloadHeaderCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_header_deneb"))]
    pub execution: ExecutionPayloadHeaderDeneb<E>,
    #[superstruct(
        only(Electra),
        partial_getter(rename = "execution_payload_header_electra")
    )]
    pub execution: ExecutionPayloadHeaderElectra<E>,
    #[superstruct(only(Fulu), partial_getter(rename = "execution_payload_header_fulu"))]
    pub execution: ExecutionPayloadHeaderFulu<E>,
    #[superstruct(only(Gloas), partial_getter(rename = "execution_payload_header_gloas"))]
    pub execution: ExecutionPayloadHeaderGloas<E>,

    #[superstruct(only(Capella, Deneb, Electra, Fulu, Gloas))]
    pub execution_branch: FixedVector<Hash256, ExecutionPayloadProofLen>,

    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[serde(skip)]
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub _phantom_data: PhantomData<E>,
}

impl<E: EthSpec> LightClientHeader<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
        chain_spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let header = match block
            .fork_name(chain_spec)
            .map_err(|_| Error::InconsistentFork)?
        {
            ForkName::Base => return Err(Error::AltairForkNotActive),
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
            ForkName::Gloas => LightClientHeader::Gloas(
                LightClientHeaderGloas::block_to_light_client_header(block)?,
            ),
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
            ForkName::Gloas => {
                LightClientHeader::Gloas(LightClientHeaderGloas::from_ssz_bytes(bytes)?)
            }
            ForkName::Base => {
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
        if fork_name.capella_enabled() {
            ExecutionPayloadHeader::<E>::ssz_max_var_len_for_fork(fork_name)
        } else {
            0
        }
    }
}

impl<E: EthSpec> LightClientHeaderAltair<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, Error> {
        Ok(LightClientHeaderAltair {
            beacon: block.message().block_header(),
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> Default for LightClientHeaderAltair<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderCapella<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, Error> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_capella()?;

        let header = ExecutionPayloadHeaderCapella::from(payload);
        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_capella()
                .map_err(|_| Error::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderCapella {
            beacon: block.message().block_header(),
            execution: header,
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> Default for LightClientHeaderCapella<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeaderCapella::default(),
            execution_branch: FixedVector::default(),
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderDeneb<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, Error> {
        let header = block
            .message()
            .execution_payload()?
            .execution_payload_deneb()?
            .clone();

        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_deneb()
                .map_err(|_| Error::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderDeneb {
            beacon: block.message().block_header(),
            execution: header,
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> Default for LightClientHeaderDeneb<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeaderDeneb::default(),
            execution_branch: FixedVector::default(),
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderElectra<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, Error> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_electra()?;

        let header = ExecutionPayloadHeaderElectra::from(payload);
        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_electra()
                .map_err(|_| Error::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderElectra {
            beacon: block.message().block_header(),
            execution: header,
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> Default for LightClientHeaderElectra<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeaderElectra::default(),
            execution_branch: FixedVector::default(),
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderFulu<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, Error> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_fulu()?;

        let header = ExecutionPayloadHeaderFulu::from(payload);
        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_fulu()
                .map_err(|_| Error::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderFulu {
            beacon: block.message().block_header(),
            execution: header,
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> Default for LightClientHeaderFulu<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeaderFulu::default(),
            execution_branch: FixedVector::default(),
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderGloas<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, Error> {
        let payload = block
            .message()
            .execution_payload()?
            .execution_payload_gloas()?;

        let header = ExecutionPayloadHeaderGloas::from(payload);
        let beacon_block_body = BeaconBlockBody::from(
            block
                .message()
                .body_gloas()
                .map_err(|_| Error::BeaconBlockBodyError)?
                .to_owned(),
        );

        let execution_branch = beacon_block_body
            .to_ref()
            .block_body_merkle_proof(EXECUTION_PAYLOAD_INDEX)?;

        Ok(LightClientHeaderGloas {
            beacon: block.message().block_header(),
            execution: header,
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> Default for LightClientHeaderGloas<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution: ExecutionPayloadHeaderGloas::default(),
            execution_branch: FixedVector::default(),
            _phantom_data: PhantomData,
        }
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for LightClientHeader<E> {
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
            ForkName::Base => {
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
        use crate::{LightClientHeaderAltair, MainnetEthSpec};
        ssz_tests!(LightClientHeaderAltair<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod capella {
        use crate::{LightClientHeaderCapella, MainnetEthSpec};
        ssz_tests!(LightClientHeaderCapella<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod deneb {
        use crate::{LightClientHeaderDeneb, MainnetEthSpec};
        ssz_tests!(LightClientHeaderDeneb<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod electra {
        use crate::{LightClientHeaderElectra, MainnetEthSpec};
        ssz_tests!(LightClientHeaderElectra<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod fulu {
        use crate::{LightClientHeaderFulu, MainnetEthSpec};
        ssz_tests!(LightClientHeaderFulu<MainnetEthSpec>);
    }

    #[cfg(test)]
    mod gloas {
        use crate::{LightClientHeaderGloas, MainnetEthSpec};
        ssz_tests!(LightClientHeaderGloas<MainnetEthSpec>);
    }
}
