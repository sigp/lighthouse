use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

pub type Transaction<N> = VariableList<u8, N>;
pub type Transactions<E> = VariableList<
    Transaction<<E as EthSpec>::MaxBytesPerTransaction>,
    <E as EthSpec>::MaxTransactionsPerPayload,
>;

pub type Withdrawals<E> = VariableList<Withdrawal, <E as EthSpec>::MaxWithdrawalsPerPayload>;

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, EIP7732),
    variant_attributes(
        derive(
            Default,
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom,
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec")
    ),
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant")
)]
#[derive(
    Debug, Clone, Serialize, Encode, Deserialize, TreeHash, Derivative, arbitrary::Arbitrary,
)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(bound = "E: EthSpec", untagged)]
#[arbitrary(bound = "E: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionPayload<E: EthSpec> {
    #[superstruct(getter(copy))]
    pub parent_hash: ExecutionBlockHash,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::address_hex")]
    pub fee_recipient: Address,
    #[superstruct(getter(copy))]
    pub state_root: Hash256,
    #[superstruct(getter(copy))]
    pub receipts_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, E::BytesPerLogsBloom>,
    #[superstruct(getter(copy))]
    pub prev_randao: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub block_number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, E::MaxExtraDataBytes>,
    #[serde(with = "serde_utils::quoted_u256")]
    #[superstruct(getter(copy))]
    pub base_fee_per_gas: Uint256,
    #[superstruct(getter(copy))]
    pub block_hash: ExecutionBlockHash,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: Transactions<E>,
    #[superstruct(only(Capella, Deneb, Electra, EIP7732))]
    pub withdrawals: Withdrawals<E>,
    #[superstruct(only(Deneb, Electra, EIP7732), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub blob_gas_used: u64,
    #[superstruct(only(Deneb, Electra, EIP7732), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub excess_blob_gas: u64,
}

impl<'a, E: EthSpec> ExecutionPayloadRef<'a, E> {
    // this emulates clone on a normal reference type
    pub fn clone_from_ref(&self) -> ExecutionPayload<E> {
        map_execution_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.clone().into()
        })
    }
}

impl<E: EthSpec> ExecutionPayload<E> {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            // FIXME(EIP7732): Check this
            ForkName::Base | ForkName::Altair => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionPayload: {fork_name}",
            ))),
            ForkName::Bellatrix => {
                ExecutionPayloadBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => ExecutionPayloadCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => ExecutionPayloadDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
            ForkName::Electra => ExecutionPayloadElectra::from_ssz_bytes(bytes).map(Self::Electra),
            ForkName::EIP7732 => ExecutionPayloadEIP7732::from_ssz_bytes(bytes).map(Self::EIP7732),
        }
    }

    #[allow(clippy::arithmetic_side_effects)]
    /// Returns the maximum size of an execution payload.
    pub fn max_execution_payload_bellatrix_size() -> usize {
        // Fixed part
        ExecutionPayloadBellatrix::<E>::default().as_ssz_bytes().len()
            // Max size of variable length `extra_data` field
            + (E::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
            // Max size of variable length `transactions` field
            + (E::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + E::max_bytes_per_transaction()))
    }

    #[allow(clippy::arithmetic_side_effects)]
    /// Returns the maximum size of an execution payload.
    pub fn max_execution_payload_capella_size() -> usize {
        // Fixed part
        ExecutionPayloadCapella::<E>::default().as_ssz_bytes().len()
            // Max size of variable length `extra_data` field
            + (E::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
            // Max size of variable length `transactions` field
            + (E::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + E::max_bytes_per_transaction()))
            // Max size of variable length `withdrawals` field
            + (E::max_withdrawals_per_payload() * <Withdrawal as Encode>::ssz_fixed_len())
    }

    #[allow(clippy::arithmetic_side_effects)]
    /// Returns the maximum size of an execution payload.
    pub fn max_execution_payload_deneb_size() -> usize {
        // Fixed part
        ExecutionPayloadDeneb::<E>::default().as_ssz_bytes().len()
            // Max size of variable length `extra_data` field
            + (E::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
            // Max size of variable length `transactions` field
            + (E::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + E::max_bytes_per_transaction()))
            // Max size of variable length `withdrawals` field
            + (E::max_withdrawals_per_payload() * <Withdrawal as Encode>::ssz_fixed_len())
    }

    #[allow(clippy::arithmetic_side_effects)]
    /// Returns the maximum size of an execution payload.
    pub fn max_execution_payload_electra_size() -> usize {
        // Fixed part
        ExecutionPayloadElectra::<E>::default().as_ssz_bytes().len()
            // Max size of variable length `extra_data` field
            + (E::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
            // Max size of variable length `transactions` field
            + (E::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + E::max_bytes_per_transaction()))
            // Max size of variable length `withdrawals` field
            + (E::max_withdrawals_per_payload() * <Withdrawal as Encode>::ssz_fixed_len())
    }

    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_execution_payload_eip7732_size() -> usize {
        // Fixed part
        ExecutionPayloadEIP7732::<E>::default().as_ssz_bytes().len()
        + (E::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
        // Max size of variable length `transactions` field
        + (E::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + E::max_bytes_per_transaction()))
        // Max size of variable length `withdrawals` field
        + (E::max_withdrawals_per_payload() * <Withdrawal as Encode>::ssz_fixed_len())
    }
}

impl<E: EthSpec> ForkVersionDeserialize for ExecutionPayload<E> {
    fn deserialize_by_fork<'de, D: serde::Deserializer<'de>>(
        value: serde_json::value::Value,
        fork_name: ForkName,
    ) -> Result<Self, D::Error> {
        let convert_err = |e| {
            serde::de::Error::custom(format!("ExecutionPayload failed to deserialize: {:?}", e))
        };

        Ok(match fork_name {
            ForkName::Bellatrix => {
                Self::Bellatrix(serde_json::from_value(value).map_err(convert_err)?)
            }
            ForkName::Capella => Self::Capella(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Deneb => Self::Deneb(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Electra => Self::Electra(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::EIP7732 => Self::EIP7732(serde_json::from_value(value).map_err(convert_err)?),
            ForkName::Base | ForkName::Altair => {
                return Err(serde::de::Error::custom(format!(
                    "ExecutionPayload failed to deserialize: unsupported fork '{}'",
                    fork_name
                )));
            }
        })
    }
}

impl<E: EthSpec> ExecutionPayload<E> {
    pub fn fork_name(&self) -> ForkName {
        match self {
            ExecutionPayload::Bellatrix(_) => ForkName::Bellatrix,
            ExecutionPayload::Capella(_) => ForkName::Capella,
            ExecutionPayload::Deneb(_) => ForkName::Deneb,
            ExecutionPayload::Electra(_) => ForkName::Electra,
            ExecutionPayload::EIP7732(_) => ForkName::EIP7732,
        }
    }
}
