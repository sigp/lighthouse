use super::KzgCommitment;
use crate::{
    AbstractExecPayload, ChainSpec, EthSpec, ExecPayload, ExecutionPayloadHeader, SignedRoot,
    Uint256, MainnetEthSpec,
};
use bls::PublicKeyBytes;
use bls::Signature;
use serde::{Deserialize as De, Deserializer, Serialize as Ser, Serializer};
use serde_derive::{Deserialize, Serialize};
use serde_with::As;
use serde_with::{serde_as, DeserializeAs, SerializeAs};
use ssz_types::VariableList;
use superstruct::superstruct;
use std::marker::PhantomData;
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Bellatrix, Eip4844),
    variant_attributes(
        derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone),
        serde(bound = "E: EthSpec, Payload: ExecPayload<E>", deny_unknown_fields)
    )
)]
#[derive(PartialEq, Debug, Serialize, Deserialize, TreeHash, Clone)]
#[serde(bound = "E: EthSpec, Payload: ExecPayload<E>", deny_unknown_fields)]
#[tree_hash(enum_behaviour = "transparent")]
pub struct BuilderBid<E: EthSpec, Payload: AbstractExecPayload<E>> {
    #[serde(with = "As::<BlindedPayloadAsHeader<E>>")]
    pub header: Payload,
    #[serde(with = "eth2_serde_utils::quoted_u256")]
    pub value: Uint256,
    pub pubkey: PublicKeyBytes,
    // #[superstruct(only(Eip4844))]
    // pub blob_kzg_commitments: VariableList<KzgCommitment, E::MaxBlobsPerBlock>,
    #[serde(skip)]
    #[tree_hash(skip_hashing)]
    _phantom_data: PhantomData<E>,
}

#[derive(Debug)]
pub enum SerdeError {
    Serde(serde_json::Error)
}

impl From<serde_json::Error> for SerdeError {
    fn from(err: serde_json::Error) -> Self {
        SerdeError::Serde(err)
    }
}

pub fn deserialize_bid<E: EthSpec, Payload: AbstractExecPayload<E>>(str: &str) -> Result<BuilderBid<E, Payload>, SerdeError> {
    dbg!(str);
    let bid = serde_json::from_str(str)?;
    Ok(bid)
}


#[superstruct(
    variants(A,B),
    variant_attributes(derive(Debug, Serialize, Deserialize))
)]
#[derive(Debug, Serialize, Deserialize)]
pub struct BasicStruct {
    #[serde(with = "eth2_serde_utils::quoted_u8")]
    pub field: u8,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    #[superstruct(only(A))]
    pub fieldA: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    #[superstruct(only(B))]
    pub fieldB: u64
}

#[cfg(test)]
mod tests {
    use log::debug;
    use crate::{ExecutionPayload, BlindedPayload, ExecutionPayloadHeaderEip4844};
    use super::*;
    
    #[test]
    fn test_serialize() {
        let a = BasicStructA {
            field: 1,
            fieldA: 2,
        };
        print!("{}", serde_json::to_string_pretty(&a).unwrap());
    }

    #[test]
    fn test_deserialize() {
        let a = r#"{
            field: 1,
            fieldA: 2,
        }"#;
        dbg!(serde_json::from_str::<BasicStruct>(a));
    }

    // #[test]
    fn test_deserialize_bid() {
        let str = r#"{
            "header": {
              "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
              "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
              "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "block_number": "1",
              "gas_limit": "1",
              "gas_used": "1",
              "timestamp": "1",
              "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "base_fee_per_gas": "1",
              "excess_data_gas": "1",
              "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
              "transactions_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
            },
            "value": "1",
            "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
            "blob_kzg_commitments": [
        "0xa94170080872584e54a1cf092d845703b13907f2e6b3b1c0ad573b910530499e3bcd48c6378846b80d2bfa58c81cf3d5"
            ]
          }"#;
        let result = deserialize_bid::<MainnetEthSpec, BlindedPayload<MainnetEthSpec>>(str);
        dbg!(result);
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
