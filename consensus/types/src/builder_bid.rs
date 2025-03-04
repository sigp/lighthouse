use crate::beacon_block_body::KzgCommitments;
use crate::{
    ChainSpec, EthSpec, ExecutionPayloadHeaderBellatrix, ExecutionPayloadHeaderCapella,
    ExecutionPayloadHeaderDeneb, ExecutionPayloadHeaderElectra, ExecutionPayloadHeaderFulu,
    ExecutionPayloadHeaderRef, ExecutionPayloadHeaderRefMut, ExecutionRequests, ForkName,
    ForkVersionDecode, ForkVersionDeserialize, SignedRoot, Uint256,
};
use bls::PublicKeyBytes;
use bls::Signature;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu),
    variant_attributes(
        derive(
            PartialEq,
            Debug,
            Encode,
            Serialize,
            Deserialize,
            TreeHash,
            Decode,
            Clone
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
    #[superstruct(only(Deneb, Electra, Fulu))]
    pub blob_kzg_commitments: KzgCommitments<E>,
    #[superstruct(only(Electra, Fulu))]
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
                )))
            }
            ForkName::Bellatrix => {
                BuilderBid::Bellatrix(BuilderBidBellatrix::from_ssz_bytes(bytes)?)
            }
            ForkName::Capella => BuilderBid::Capella(BuilderBidCapella::from_ssz_bytes(bytes)?),
            ForkName::Deneb => BuilderBid::Deneb(BuilderBidDeneb::from_ssz_bytes(bytes)?),
            ForkName::Electra => BuilderBid::Electra(BuilderBidElectra::from_ssz_bytes(bytes)?),
            ForkName::Fulu => BuilderBid::Fulu(BuilderBidFulu::from_ssz_bytes(bytes)?),
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

impl<E: EthSpec> ForkVersionDeserialize for BuilderBid<E> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        let convert_err =
            |e| serde::de::Error::custom(format!("BuilderBid failed to deserialize: {:?}", e));

        Ok(match fork_name {
            ForkName::Bellatrix => {
                Self::Bellatrix(serde_json::from_value(value).map_err(convert_err)?)
            }
            ForkName::Capella => Self::Capella(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Deneb => Self::Deneb(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Electra => Self::Electra(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Fulu => Self::Fulu(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Base | ForkName::Altair => {
                return Err(serde::de::Error::custom(format!(
                    "BuilderBid failed to deserialize: unsupported fork '{}'",
                    fork_name
                )));
            }
        })
    }
}

impl<E: EthSpec> ForkVersionDeserialize for SignedBuilderBid<E> {
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            pub message: serde_json::Value,
            pub signature: Signature,
        }
        let helper: Helper = serde_json::from_value(value).map_err(serde::de::Error::custom)?;

        Ok(Self {
            message: BuilderBid::deserialize_by_fork::<'de, D>(helper.message, fork_name)?,
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
