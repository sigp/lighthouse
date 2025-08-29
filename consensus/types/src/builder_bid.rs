use crate::beacon_block_body::KzgCommitments;
use crate::{
    ChainSpec, ContextDeserialize, EthSpec, ExecutionPayloadHeaderBellatrix,
    ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb, ExecutionPayloadHeaderElectra,
    ExecutionPayloadHeaderFulu, ExecutionPayloadHeaderGloas, ExecutionPayloadHeaderRef,
    ExecutionPayloadHeaderRefMut, ExecutionRequests, ForkName, ForkVersionDecode, SignedRoot,
    Uint256, test_utils::TestRandom,
};
use bls::PublicKeyBytes;
use bls::Signature;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu, Gloas),
    variant_attributes(
        derive(
            PartialEq,
            Debug,
            Encode,
            Serialize,
            Deserialize,
            TreeHash,
            Decode,
            Clone,
            TestRandom
        ),
        serde(bound = "E: EthSpec", deny_unknown_fields)
    ),
    map_ref_into(ExecutionPayloadHeaderRef),
    map_ref_mut_into(ExecutionPayloadHeaderRefMut)
)]
#[derive(PartialEq, Debug, Encode, Serialize, Deserialize, TreeHash, Clone)]
#[serde(bound = "E: EthSpec", deny_unknown_fields, untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct BuilderBid<E: EthSpec> {
    #[superstruct(only(Bellatrix), partial_getter(rename = "header_bellatrix"))]
    pub header: ExecutionPayloadHeaderBellatrix<E>,
    #[superstruct(only(Capella), partial_getter(rename = "header_capella"))]
    pub header: ExecutionPayloadHeaderCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "header_deneb"))]
    pub header: ExecutionPayloadHeaderDeneb<E>,
    #[superstruct(only(Electra), partial_getter(rename = "header_electra"))]
    pub header: ExecutionPayloadHeaderElectra<E>,
    #[superstruct(only(Fulu), partial_getter(rename = "header_fulu"))]
    pub header: ExecutionPayloadHeaderFulu<E>,
    #[superstruct(only(Gloas), partial_getter(rename = "header_gloas"))]
    pub header: ExecutionPayloadHeaderGloas<E>,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas))]
    pub blob_kzg_commitments: KzgCommitments<E>,
    #[superstruct(only(Electra, Fulu, Gloas))]
    pub execution_requests: ExecutionRequests<E>,
    #[serde(with = "serde_utils::quoted_u256")]
    pub value: Uint256,
    pub pubkey: PublicKeyBytes,
}

impl<E: EthSpec> BuilderBid<E> {
    pub fn header(&self) -> ExecutionPayloadHeaderRef<'_, E> {
        self.to_ref().header()
    }
}

impl<'a, E: EthSpec> BuilderBidRef<'a, E> {
    pub fn header(&self) -> ExecutionPayloadHeaderRef<'a, E> {
        map_builder_bid_ref_into_execution_payload_header_ref!(&'a _, self, |bid, cons| cons(
            &bid.header
        ))
    }
}

impl<'a, E: EthSpec> BuilderBidRefMut<'a, E> {
    pub fn header_mut(self) -> ExecutionPayloadHeaderRefMut<'a, E> {
        map_builder_bid_ref_mut_into_execution_payload_header_ref_mut!(&'a _, self, |bid, cons| {
            cons(&mut bid.header)
        })
    }
}

impl<E: EthSpec> ForkVersionDecode for BuilderBid<E> {
    /// SSZ decode with explicit fork variant.
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let builder_bid = match fork_name {
            ForkName::Altair | ForkName::Base => {
                return Err(ssz::DecodeError::BytesInvalid(format!(
                    "unsupported fork for ExecutionPayloadHeader: {fork_name}",
                )));
            }
            ForkName::Bellatrix => {
                BuilderBid::Bellatrix(BuilderBidBellatrix::from_ssz_bytes(bytes)?)
            }
            ForkName::Capella => BuilderBid::Capella(BuilderBidCapella::from_ssz_bytes(bytes)?),
            ForkName::Deneb => BuilderBid::Deneb(BuilderBidDeneb::from_ssz_bytes(bytes)?),
            ForkName::Electra => BuilderBid::Electra(BuilderBidElectra::from_ssz_bytes(bytes)?),
            ForkName::Fulu => BuilderBid::Fulu(BuilderBidFulu::from_ssz_bytes(bytes)?),
            ForkName::Gloas => BuilderBid::Gloas(BuilderBidGloas::from_ssz_bytes(bytes)?),
        };
        Ok(builder_bid)
    }
}

impl<E: EthSpec> SignedRoot for BuilderBid<E> {}

/// Validator registration, for use in interacting with servers implementing the builder API.
#[derive(PartialEq, Debug, Encode, Serialize, Deserialize, Clone)]
#[serde(bound = "E: EthSpec")]
pub struct SignedBuilderBid<E: EthSpec> {
    pub message: BuilderBid<E>,
    pub signature: Signature,
}

impl<E: EthSpec> ForkVersionDecode for SignedBuilderBid<E> {
    /// SSZ decode with explicit fork variant.
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);

        builder.register_anonymous_variable_length_item()?;
        builder.register_type::<Signature>()?;

        let mut decoder = builder.build()?;
        let message = decoder
            .decode_next_with(|bytes| BuilderBid::from_ssz_bytes_by_fork(bytes, fork_name))?;
        let signature = decoder.decode_next()?;

        Ok(Self { message, signature })
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for BuilderBid<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err =
            |e| serde::de::Error::custom(format!("BuilderBid failed to deserialize: {:?}", e));
        Ok(match context {
            ForkName::Bellatrix => {
                Self::Bellatrix(Deserialize::deserialize(deserializer).map_err(convert_err)?)
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
            ForkName::Base | ForkName::Altair => {
                return Err(serde::de::Error::custom(format!(
                    "BuilderBid failed to deserialize: unsupported fork '{}'",
                    context
                )));
            }
        })
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for SignedBuilderBid<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            message: serde_json::Value,
            signature: Signature,
        }

        let helper = Helper::deserialize(deserializer)?;

        // Deserialize `data` using ContextDeserialize
        let message = BuilderBid::<E>::context_deserialize(helper.message, context)
            .map_err(serde::de::Error::custom)?;

        Ok(SignedBuilderBid {
            message,
            signature: helper.signature,
        })
    }
}

impl<E: EthSpec> SignedBuilderBid<E> {
    pub fn verify_signature(&self, spec: &ChainSpec) -> bool {
        self.message
            .pubkey()
            .decompress()
            .map(|pubkey| {
                let domain = spec.get_builder_domain();
                let message = self.message.signing_root(domain);
                self.signature.verify(&pubkey, message)
            })
            .unwrap_or(false)
    }
}
