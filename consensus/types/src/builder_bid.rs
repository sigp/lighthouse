use crate::beacon_block_body::KzgCommitments;
use crate::{
    BlobRootsList, BlobsBundle, ChainSpec, EthSpec, ExecutionPayloadHeaderCapella,
    ExecutionPayloadHeaderDeneb, ExecutionPayloadHeaderMerge, ExecutionPayloadHeaderRef, ForkName,
    ForkVersionDeserialize, KzgProofs, SignedRoot, Uint256,
};
use bls::PublicKeyBytes;
use bls::Signature;
use serde::Deserializer;
use serde_derive::{Deserialize, Serialize};
use ssz_derive::Encode;
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(PartialEq, Debug, Default, Serialize, Deserialize, TreeHash, Clone, Encode)]
#[serde(bound = "E: EthSpec")]
pub struct BlindedBlobsBundle<E: EthSpec> {
    pub commitments: KzgCommitments<E>,
    pub proofs: KzgProofs<E>,
    pub blob_roots: BlobRootsList<E>,
}

impl<E: EthSpec> From<BlobsBundle<E>> for BlindedBlobsBundle<E> {
    fn from(blobs_bundle: BlobsBundle<E>) -> Self {
        BlindedBlobsBundle {
            commitments: blobs_bundle.commitments,
            proofs: blobs_bundle.proofs,
            blob_roots: blobs_bundle
                .blobs
                .into_iter()
                .map(|blob| blob.tree_hash_root())
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

#[superstruct(
    variants(Merge, Capella, Deneb),
    variant_attributes(
        derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone),
        serde(bound = "E: EthSpec", deny_unknown_fields)
    ),
    map_ref_into(ExecutionPayloadHeaderRef)
)]
#[derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone)]
#[serde(bound = "E: EthSpec", deny_unknown_fields, untagged)]
#[tree_hash(enum_behaviour = "transparent")]
pub struct BuilderBid<E: EthSpec> {
    #[superstruct(only(Merge), partial_getter(rename = "header_merge"))]
    pub header: ExecutionPayloadHeaderMerge<E>,
    #[superstruct(only(Capella), partial_getter(rename = "header_capella"))]
    pub header: ExecutionPayloadHeaderCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "header_deneb"))]
    pub header: ExecutionPayloadHeaderDeneb<E>,
    #[superstruct(only(Deneb))]
    pub blinded_blobs_bundle: BlindedBlobsBundle<E>,
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

impl<E: EthSpec> SignedRoot for BuilderBid<E> {}

/// Validator registration, for use in interacting with servers implementing the builder API.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "E: EthSpec")]
pub struct SignedBuilderBid<E: EthSpec> {
    pub message: BuilderBid<E>,
    pub signature: Signature,
}

impl<T: EthSpec> ForkVersionDeserialize for BuilderBid<T> {
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

impl<T: EthSpec> ForkVersionDeserialize for SignedBuilderBid<T> {
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
