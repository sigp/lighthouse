use crate::beacon_block_body::KzgCommitments;
use crate::{
    AbstractExecPayload, ChainSpec, EthSpec, ExecPayload, ExecutionPayloadHeader, ForkName,
    ForkVersionDeserialize, Hash256, KzgProofs, SignedRoot, Uint256,
};
use bls::PublicKeyBytes;
use bls::Signature;
use serde::{Deserialize as De, Deserializer, Serialize as Ser, Serializer};
use serde_derive::{Deserialize, Serialize};
use serde_with::As;
use serde_with::{DeserializeAs, SerializeAs};
use ssz_types::VariableList;
use std::marker::PhantomData;
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone)]
#[serde(bound = "E: EthSpec")]
pub struct BlindedBlobsBundle<E: EthSpec> {
    pub commitments: KzgCommitments<E>,
    pub proofs: KzgProofs<E>,
    pub blob_roots: VariableList<Hash256, E::MaxBlobsPerBlock>,
}

#[superstruct(
    variants(Merge, Capella, Deneb),
    variant_attributes(
        derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone),
        serde(bound = "E: EthSpec, Payload: ExecPayload<E>", deny_unknown_fields)
    )
)]
#[derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone)]
#[serde(
    bound = "E: EthSpec, Payload: ExecPayload<E>",
    deny_unknown_fields,
    untagged
)]
#[tree_hash(enum_behaviour = "transparent")]
pub struct BuilderBid<E: EthSpec, Payload: AbstractExecPayload<E>> {
    #[serde(with = "As::<BlindedPayloadAsHeader<E>>")]
    pub header: Payload,
    #[superstruct(only(Deneb))]
    pub blinded_blobs_bundle: BlindedBlobsBundle<E>,
    #[serde(with = "serde_utils::quoted_u256")]
    pub value: Uint256,
    pub pubkey: PublicKeyBytes,
    #[serde(skip)]
    #[tree_hash(skip_hashing)]
    _phantom_data: PhantomData<E>,
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

struct BlindedPayloadAsHeader<E>(PhantomData<E>);

impl<E: EthSpec, Payload: ExecPayload<E>> SerializeAs<Payload> for BlindedPayloadAsHeader<E> {
    fn serialize_as<S>(source: &Payload, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        source.to_execution_payload_header().serialize(serializer)
    }
}

impl<'de, E: EthSpec, Payload: AbstractExecPayload<E>> DeserializeAs<'de, Payload>
    for BlindedPayloadAsHeader<E>
{
    fn deserialize_as<D>(deserializer: D) -> Result<Payload, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload_header = ExecutionPayloadHeader::deserialize(deserializer)?;
        Payload::try_from(payload_header)
            .map_err(|_| serde::de::Error::custom("unable to convert payload header to payload"))
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
