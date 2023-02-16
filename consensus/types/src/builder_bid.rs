use super::KzgCommitment;
use crate::{
    AbstractExecPayload, ChainSpec, EthSpec, ExecPayload, ExecutionPayloadHeader, ForkName,
    ForkVersionDeserialize, SignedRoot, Uint256,
};
use bls::PublicKeyBytes;
use bls::Signature;
use serde::{Deserialize as De, Deserializer, Serialize as Ser, Serializer};
use serde_derive::{Deserialize, Serialize};
use serde_with::{As, DeserializeAs, SerializeAs};
use ssz_types::VariableList;
use std::marker::PhantomData;
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

#[superstruct(
    variants(Merge, Eip4844),
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

    #[serde(with = "eth2_serde_utils::quoted_u256")]
    pub value: Uint256,
    pub pubkey: PublicKeyBytes,

    #[superstruct(only(Eip4844))]
    pub blob_kzg_commitments: VariableList<KzgCommitment, E::MaxBlobsPerBlock>,

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
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        let convert_err = |_| {
            serde::de::Error::custom(
                "BuilderBid failed to deserialize: unable to convert payload header to payload",
            )
        };

        #[derive(Deserialize)]
        struct Helper {
            header: serde_json::Value,
            #[serde(with = "eth2_serde_utils::quoted_u256")]
            value: Uint256,
            pubkey: PublicKeyBytes,
        }
        let helper: Helper = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        let payload_header =
            ExecutionPayloadHeader::deserialize_by_fork::<'de, D>(helper.header, fork_name)?;

        match fork_name {
            ForkName::Base | ForkName::Altair => Err(serde::de::Error::custom(
                "BuilderBid failed to deserialize: unable to convert payload header to payload",
            )),
            ForkName::Merge | ForkName::Capella => Ok(BuilderBid::Merge(BuilderBidMerge {
                header: Payload::try_from(payload_header).map_err(convert_err)?,
                value: helper.value,
                pubkey: helper.pubkey,
                _phantom_data: PhantomData,
            })),
            ForkName::Eip4844 => Ok(BuilderBid::Eip4844(BuilderBidEip4844 {
                header: Payload::try_from(payload_header).map_err(convert_err)?,
                value: helper.value,
                pubkey: helper.pubkey,
                // TODO
                blob_kzg_commitments: VariableList::empty(),
                _phantom_data: PhantomData,
            })),
        }
    }
}

impl<T: EthSpec, Payload: AbstractExecPayload<T>> ForkVersionDeserialize
    for SignedBuilderBid<T, Payload>
{
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlindedPayload, MainnetEthSpec};

    type Spec = MainnetEthSpec;
    type Payload = BlindedPayload<Spec>;

    fn deserialize_bid(str: &str) -> BuilderBid<Spec, Payload> {
        serde_json::from_str(str).expect("should deserialize to BuilderBid")
    }

    fn serialize_bid(bid: BuilderBid<Spec, Payload>) -> String {
        serde_json::to_string(&bid).expect("should serialize to json string")
    }

    fn to_minified_json(json: &str) -> String {
        let mut json_mut = String::from(json);
        json_mut.retain(|c| !c.is_whitespace());
        json_mut
    }

    #[test]
    fn test_serde_builder_bid_merge() {
        let expected_json = to_minified_json(
            r#"{
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
                  "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                  "transactions_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                },
                "value": "1",
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
            }"#,
        );
        let bid = deserialize_bid(&expected_json);
        let actual_json = serialize_bid(bid);
        assert_eq!(actual_json, expected_json);
    }

    #[test]
    fn test_serde_builder_bid_capella() {
        let expected_json = to_minified_json(
            r#"{
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
                  "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                  "transactions_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                  "withdrawals_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                },
                "value": "1",
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
            }"#,
        );
        let bid = deserialize_bid(&expected_json);
        let actual_json = serialize_bid(bid);
        assert_eq!(actual_json, expected_json);
    }

    #[test]
    fn test_serde_builder_bid_eip4844() {
        let expected_json = to_minified_json(
            r#"{
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
                  "transactions_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
                  "withdrawals_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
                },
                "value": "1",
                "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
                "blob_kzg_commitments": [
            "0xa94170080872584e54a1cf092d845703b13907f2e6b3b1c0ad573b910530499e3bcd48c6378846b80d2bfa58c81cf3d5"
                ]
            }"#,
        );
        let bid = deserialize_bid(&expected_json);
        let actual_json = serialize_bid(bid);
        assert_eq!(actual_json, expected_json);
    }
}
