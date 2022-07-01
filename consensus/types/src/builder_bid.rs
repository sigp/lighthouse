use crate::{EthSpec, ExecPayload, ExecutionPayloadHeader, Uint256};
use bls::blst_implementations::PublicKeyBytes;
use bls::Signature;
use serde::{Deserialize as De, Deserializer, Serialize as Ser, Serializer};
use serde_derive::{Deserialize, Serialize};
use serde_with::{serde_as, DeserializeAs, SerializeAs};
use std::marker::PhantomData;

#[serde_as]
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "E: EthSpec, Payload: ExecPayload<E>")]
pub struct BuilderBid<E: EthSpec, Payload: ExecPayload<E>> {
    #[serde_as(as = "BlindedPayloadAsHeader<E>")]
    pub header: Payload,
    #[serde(with = "eth2_serde_utils::quoted_u256")]
    pub value: Uint256,
    pub pubkey: PublicKeyBytes,
    #[serde(skip)]
    _phantom_data: PhantomData<E>,
}

/// Validator registration, for use in interacting with servers implementing the builder API.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "E: EthSpec, Payload: ExecPayload<E>")]
pub struct SignedBuilderBid<E: EthSpec, Payload: ExecPayload<E>> {
    pub message: BuilderBid<E, Payload>,
    pub signature: Signature,
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

impl<'de, E: EthSpec, Payload: ExecPayload<E>> DeserializeAs<'de, Payload>
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
