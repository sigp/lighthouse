use crate::beacon_block_body::KzgCommitments;
use crate::{
    AbstractExecPayload, BlobRootsList, ChainSpec, EthSpec, ExecPayload, ForkName,
    ForkVersionDeserialize, KzgProofs, SignedRoot, Uint256,
};
use bls::PublicKeyBytes;
use bls::Signature;
use serde::Deserializer;
use serde_derive::{Deserialize, Serialize};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone)]
#[serde(bound = "E: EthSpec")]
pub struct BlindedBlobsBundle<E: EthSpec> {
    pub commitments: KzgCommitments<E>,
    pub proofs: KzgProofs<E>,
    pub blob_roots: BlobRootsList<E>,
}

#[superstruct(
    variants(Merge, Capella, Deneb),
    variant_attributes(
        derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone),
        serde(
            bound = "E: EthSpec, Payload: AbstractExecPayload<E>",
            deny_unknown_fields
        )
    )
)]
#[derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone)]
#[serde(
    bound = "E: EthSpec, Payload: AbstractExecPayload<E>",
    deny_unknown_fields,
    untagged
)]
#[tree_hash(enum_behaviour = "transparent")]
pub struct BuilderBid<E: EthSpec, Payload: AbstractExecPayload<E>> {
    #[superstruct(only(Merge), partial_getter(rename = "header_merge"))]
    pub header: Payload::Merge,
    #[superstruct(only(Capella), partial_getter(rename = "header_capella"))]
    pub header: Payload::Capella,
    #[superstruct(only(Deneb), partial_getter(rename = "header_deneb"))]
    pub header: Payload::Deneb,
    #[superstruct(only(Deneb))]
    pub blinded_blobs_bundle: BlindedBlobsBundle<E>,
    #[serde(with = "serde_utils::quoted_u256")]
    pub value: Uint256,
    pub pubkey: PublicKeyBytes,
}

impl<E: EthSpec, Payload: AbstractExecPayload<E>> BuilderBid<E, Payload> {
    pub fn header(&self) -> Payload::Ref<'_> {
        self.to_ref().header()
    }
}

impl<'a, T: EthSpec, Payload: AbstractExecPayload<T>> BuilderBidRef<'a, T, Payload> {
    pub fn header(&self) -> Payload::Ref<'a> {
        match self {
            Self::Merge(bid) => Payload::Ref::from(&bid.header),
            Self::Capella(bid) => Payload::Ref::from(&bid.header),
            Self::Deneb(bid) => Payload::Ref::from(&bid.header),
        }
    }
}

impl<E: EthSpec, Payload: AbstractExecPayload<E>> SignedRoot for BuilderBid<E, Payload> {}

/// Validator registration, for use in interacting with servers implementing the builder API.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "E: EthSpec, Payload: ExecPayload<E>")]
pub struct SignedBuilderBid<E: EthSpec, Payload: AbstractExecPayload<E>> {
    pub message: BuilderBid<E, Payload>,
    pub signature: Signature,
}

impl<T: EthSpec, Payload: AbstractExecPayload<T>> ForkVersionDeserialize
    for BuilderBid<T, Payload>
{
    fn deserialize_by_fork<'de, D: Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        let convert_err =
            |e| serde::de::Error::custom(format!("BuilderBid failed to deserialize: {:?}", e));

        Ok(match fork_name {
            ForkName::Merge => Self::Merge(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Capella => Self::Capella(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Deneb => Self::Deneb(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Base | ForkName::Altair => {
                return Err(serde::de::Error::custom(format!(
                    "BuilderBid failed to deserialize: unsupported fork '{}'",
                    fork_name
                )));
            }
        })
    }
}

impl<T: EthSpec, Payload: AbstractExecPayload<T>> ForkVersionDeserialize
    for SignedBuilderBid<T, Payload>
{
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

impl<E: EthSpec, Payload: AbstractExecPayload<E>> SignedBuilderBid<E, Payload> {
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
