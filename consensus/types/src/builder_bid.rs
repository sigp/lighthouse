use crate::beacon_block_body::KzgCommitments;
use crate::{
    ChainSpec, EthSpec, ExecutionPayloadHeaderBellatrix, ExecutionPayloadHeaderCapella,
    ExecutionPayloadHeaderDeneb, ExecutionPayloadHeaderElectra, ExecutionPayloadHeaderRef,
    ExecutionPayloadHeaderRefMut, ForkName, ForkVersionDeserialize, SignedRoot, Uint256,
};
use bls::PublicKeyBytes;
use bls::Signature;
use serde::{Deserialize, Deserializer, Serialize};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra),
    variant_attributes(
        derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone),
        serde(bound = "E: EthSpec", deny_unknown_fields)
    ),
    map_ref_into(ExecutionPayloadHeaderRef),
    map_ref_mut_into(ExecutionPayloadHeaderRefMut)
)]
#[derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone)]
#[serde(bound = "E: EthSpec", deny_unknown_fields, untagged)]
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
    #[superstruct(only(Deneb, Electra))]
    pub blob_kzg_commitments: KzgCommitments<E>,
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

impl<E: EthSpec> SignedRoot for BuilderBid<E> {}

/// Validator registration, for use in interacting with servers implementing the builder API.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "E: EthSpec")]
pub struct SignedBuilderBid<E: EthSpec> {
    pub message: BuilderBid<E>,
    pub signature: Signature,
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
            // FIXME(EIP-7732): Check this
            ForkName::Base | ForkName::Altair | ForkName::EIP7732 => {
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
