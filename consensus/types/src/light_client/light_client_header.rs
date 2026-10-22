use std::marker::PhantomData;

use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use merkle_proof::MerkleTree;
use safe_arith::SafeArith;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::FixedVector;
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    AbstractExecPayload, BeaconBlockBodyRef, ExecutionBlockHash,
    block::{BeaconBlockBody, BeaconBlockHeader, SignedBlindedBeaconBlock},
    core::{ChainSpec, EthSpec, Hash256},
    execution::{
        ExecutionPayloadHeader, ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb,
        ExecutionPayloadHeaderElectra, ExecutionPayloadHeaderFulu,
    },
    fork::ForkName,
    light_client::{
        ExecutionBlockHashProofLenGloas, ExecutionPayloadProofLen, LightClientError,
        consts::{
            EXECUTION_BLOCK_HASH_GINDEX_DENEB, EXECUTION_BLOCK_HASH_INDEX_GLOAS,
            EXECUTION_BLOCK_HASH_PROOF_LEN_GLOAS, EXECUTION_PAYLOAD_HEADER_BLOCK_HASH_FIELD_INDEX,
            EXECUTION_PAYLOAD_INDEX, EXECUTION_PAYLOAD_PROOF_LEN,
        },
    },
    state::BeaconStateError,
};

#[superstruct(
    variants(Altair, Capella, Deneb, Electra, Fulu, Gloas),
    variant_attributes(
        derive(Debug, Clone, Serialize, Deserialize, Educe, Decode, Encode, TreeHash,),
        educe(PartialEq),
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

    #[superstruct(only(Gloas))]
    pub execution_block_hash: ExecutionBlockHash,

    #[superstruct(only(Capella, Deneb, Electra, Fulu))]
    pub execution_branch: FixedVector<Hash256, ExecutionPayloadProofLen>,
    #[superstruct(only(Gloas), partial_getter(rename = "execution_branch_gloas"))]
    pub execution_branch: FixedVector<Hash256, ExecutionBlockHashProofLenGloas>,

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
            ForkName::Gloas => LightClientHeader::Gloas(
                LightClientHeaderGloas::block_to_light_client_header(block)?,
            ),
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
            ForkName::Gloas => {
                LightClientHeader::Gloas(LightClientHeaderGloas::from_ssz_bytes(bytes)?)
            }
            ForkName::Base | ForkName::Heze => {
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
            // Gloas: `LightClientHeaderGloas` has no variable-length fields (`execution_block_hash`
            // is a fixed-size hash and `execution_branch` is a `FixedVector`)
            0
        } else if fork_name.capella_enabled() {
            ExecutionPayloadHeader::<E>::ssz_max_var_len_for_fork(fork_name)
        } else {
            0
        }
    }
}

impl<E: EthSpec> LightClientHeaderAltair<E> {
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, LightClientError> {
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
    /// Converts a block to a `LightClientHeaderCapella`. If the block is from Bellatrix, a
    /// `LightClientHeaderAltair` is constructed and upgraded to Capella.
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, LightClientError> {
        if block.fork_name_unchecked() == ForkName::Bellatrix {
            return Ok(
                LightClientHeaderAltair::block_to_light_client_header(block)?.upgrade_to_capella(),
            );
        }

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
    /// Converts a block to a `LightClientHeaderDeneb`. If the block is from Capella, a
    /// `LightClientHeaderCapella` is constructed and upgraded to Deneb.
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, LightClientError> {
        if block.fork_name_unchecked() == ForkName::Capella {
            return Ok(
                LightClientHeaderCapella::block_to_light_client_header(block)?.upgrade_to_deneb(),
            );
        }

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
    /// Converts a block to a `LightClientHeaderElectra`. If the block is from Deneb, a
    /// `LightClientHeaderDeneb` is constructed and upgraded to Electra.
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, LightClientError> {
        if block.fork_name_unchecked() == ForkName::Deneb {
            return Ok(
                LightClientHeaderDeneb::block_to_light_client_header(block)?.upgrade_to_electra()
            );
        }

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
    /// Converts a block to a `LightClientHeaderFulu`. If the block is from Electra, a
    /// `LightClientHeaderElectra` is constructed and upgraded to Fulu.
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, LightClientError> {
        if block.fork_name_unchecked() == ForkName::Electra {
            return Ok(
                LightClientHeaderElectra::block_to_light_client_header(block)?.upgrade_to_fulu(),
            );
        }

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

impl<E: EthSpec> LightClientHeaderAltair<E> {
    /// Spec: `upgrade_lc_header_to_capella`.
    pub fn upgrade_to_capella(self) -> LightClientHeaderCapella<E> {
        LightClientHeaderCapella {
            beacon: self.beacon,
            ..LightClientHeaderCapella::default()
        }
    }
}

impl<E: EthSpec> LightClientHeaderCapella<E> {
    /// Spec: `upgrade_lc_header_to_deneb`.
    pub fn upgrade_to_deneb(self) -> LightClientHeaderDeneb<E> {
        LightClientHeaderDeneb {
            beacon: self.beacon,
            execution: self.execution.upgrade_to_deneb(),
            execution_branch: self.execution_branch,
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderDeneb<E> {
    /// Spec: `upgrade_lc_header_to_electra`.
    pub fn upgrade_to_electra(self) -> LightClientHeaderElectra<E> {
        LightClientHeaderElectra {
            beacon: self.beacon,
            execution: self.execution.upgrade_to_electra(),
            execution_branch: self.execution_branch,
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderElectra<E> {
    /// Fulu keeps the Electra header.
    pub fn upgrade_to_fulu(self) -> LightClientHeaderFulu<E> {
        LightClientHeaderFulu {
            beacon: self.beacon,
            execution: self.execution.upgrade_to_fulu(),
            execution_branch: self.execution_branch,
            _phantom_data: PhantomData,
        }
    }
}

impl<E: EthSpec> LightClientHeaderFulu<E> {
    /// Spec: `upgrade_lc_header_to_gloas`.
    pub fn upgrade_to_gloas(self) -> Result<LightClientHeaderGloas<E>, LightClientError> {
        let leaves = self.execution.field_roots();
        let depth = (EXECUTION_BLOCK_HASH_GINDEX_DENEB.ilog2() as usize)
            .safe_sub(EXECUTION_PAYLOAD_PROOF_LEN)?;
        let (_, block_hash_branch) = MerkleTree::create(&leaves, depth)
            .generate_proof(EXECUTION_PAYLOAD_HEADER_BLOCK_HASH_FIELD_INDEX, depth)
            .map_err(BeaconStateError::MerkleTreeError)?;

        let branch_len = block_hash_branch
            .len()
            .safe_add(self.execution_branch.len())?;
        let num_extra = EXECUTION_BLOCK_HASH_PROOF_LEN_GLOAS.safe_sub(branch_len)?;
        let normalized_branch = std::iter::repeat_n(Hash256::ZERO, num_extra)
            .chain(block_hash_branch)
            .chain(self.execution_branch.iter().copied())
            .collect::<Vec<_>>();

        Ok(LightClientHeaderGloas {
            beacon: self.beacon,
            execution_block_hash: self.execution.block_hash,
            execution_branch: FixedVector::new(normalized_branch)?,
            _phantom_data: PhantomData,
        })
    }
}

impl<E: EthSpec> LightClientHeaderGloas<E> {
    /// Converts a block to a `LightClientHeaderGloas`. If the block is from Fulu, a
    /// `LightClientHeaderFulu` is constructed and upgraded to Gloas.
    pub fn block_to_light_client_header(
        block: &SignedBlindedBeaconBlock<E>,
    ) -> Result<Self, LightClientError> {
        if block.fork_name_unchecked() == ForkName::Fulu {
            return LightClientHeaderFulu::block_to_light_client_header(block)?.upgrade_to_gloas();
        }

        let body_gloas = block
            .message()
            .body_gloas()
            .map_err(|_| LightClientError::BeaconBlockBodyError)?;

        let execution_block_hash = body_gloas
            .signed_execution_payload_bid
            .message
            .parent_block_hash;

        let execution_branch = Self::execution_block_hash_merkle_proof(block.message().body())?;

        Ok(LightClientHeaderGloas {
            beacon: block.message().block_header(),
            execution_block_hash,
            execution_branch: FixedVector::new(execution_branch)?,
            _phantom_data: PhantomData,
        })
    }

    fn execution_block_hash_merkle_proof<Payload: AbstractExecPayload<E>>(
        beacon_block_body: BeaconBlockBodyRef<'_, E, Payload>,
    ) -> Result<Vec<Hash256>, LightClientError> {
        Ok(beacon_block_body.block_body_merkle_proof(EXECUTION_BLOCK_HASH_INDEX_GLOAS)?)
    }
}

impl<E: EthSpec> Default for LightClientHeaderGloas<E> {
    fn default() -> Self {
        Self {
            beacon: BeaconBlockHeader::empty(),
            execution_block_hash: ExecutionBlockHash::zero(),
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
            ForkName::Base | ForkName::Heze => {
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
        use crate::{LightClientHeaderAltair, Spec};
        ssz_tests!(LightClientHeaderAltair<Spec>);
    }

    #[cfg(test)]
    mod capella {
        use crate::{LightClientHeaderCapella, Spec};
        ssz_tests!(LightClientHeaderCapella<Spec>);
    }

    #[cfg(test)]
    mod deneb {
        use crate::{LightClientHeaderDeneb, Spec};
        ssz_tests!(LightClientHeaderDeneb<Spec>);
    }

    #[cfg(test)]
    mod electra {
        use crate::{LightClientHeaderElectra, Spec};
        ssz_tests!(LightClientHeaderElectra<Spec>);
    }

    #[cfg(test)]
    mod fulu {
        use crate::{LightClientHeaderFulu, Spec};
        ssz_tests!(LightClientHeaderFulu<Spec>);
    }

    #[cfg(test)]
    mod gloas {
        use crate::{LightClientHeaderGloas, Spec};
        ssz_tests!(LightClientHeaderGloas<Spec>);
    }

    mod upgrade {
        use crate::{
            BeaconBlock, BeaconBlockFulu, ExecutionPayloadHeaderFulu, LightClientHeaderFulu,
            LightClientHeaderGloas, SignedBeaconBlock, Spec,
            light_client::consts::EXECUTION_BLOCK_HASH_GINDEX_DENEB,
            test_utils::test_arbitrary_instance,
        };
        use bls::Signature;
        use tree_hash::TreeHash;

        #[test]
        fn fulu_header_upgrades_to_gloas_header() {
            let block = SignedBeaconBlock::from_block(
                BeaconBlock::Fulu(test_arbitrary_instance::<BeaconBlockFulu<Spec>>()),
                Signature::empty(),
            )
            .clone_as_blinded();
            let pre = LightClientHeaderFulu::block_to_light_client_header(&block).unwrap();
            let header = LightClientHeaderGloas::block_to_light_client_header(&block).unwrap();

            assert_eq!(header.beacon, pre.beacon);
            assert_eq!(header.execution_block_hash, pre.execution.block_hash);

            let depth = EXECUTION_BLOCK_HASH_GINDEX_DENEB.ilog2() as usize;
            let num_extra = header.execution_branch.len() - depth;
            let (extra, branch) = header.execution_branch.split_at(num_extra);
            assert!(extra.iter().all(|node| node.is_zero()));
            assert!(merkle_proof::verify_merkle_proof(
                header.execution_block_hash.into_root(),
                branch,
                depth,
                EXECUTION_BLOCK_HASH_GINDEX_DENEB - (1 << depth),
                header.beacon.body_root,
            ));
        }

        #[test]
        fn fulu_field_roots_match_execution_payload_header_root() {
            let header = test_arbitrary_instance::<ExecutionPayloadHeaderFulu<Spec>>();
            let leaves = header.field_roots();
            let depth = leaves.len().next_power_of_two().ilog2() as usize;

            assert_eq!(
                merkle_proof::MerkleTree::create(&leaves, depth).hash(),
                header.tree_hash_root()
            );
        }
    }
}
