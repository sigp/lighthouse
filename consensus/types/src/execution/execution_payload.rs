use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use fixed_bytes::Uint256;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, ProgressiveVariableList, VariableList};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    ListRef,
    core::{Address, EthSpec, ExecutionBlockHash, Hash256, Slot},
    fork::{ForkName, ForkVersionDecode},
    state::BeaconStateError,
    withdrawal::{Withdrawal, Withdrawals},
};

pub type Transaction<N> = VariableList<u8, N>;
pub type Transactions<E> = VariableList<
    Transaction<<E as EthSpec>::MaxBytesPerTransaction>,
    <E as EthSpec>::MaxTransactionsPerPayload,
>;

/// Progressive transactions list \[Modified in Gloas:EIP7688\].
pub type ProgressiveTransactions = ProgressiveVariableList<ProgressiveVariableList<u8>>;

/// Progressive withdrawals list \[Modified in Gloas:EIP7688\].
pub type ProgressiveWithdrawals = ProgressiveVariableList<Withdrawal>;

/// Opaque encoded block access list \[New in Gloas:EIP7928\].
pub type BlockAccessList = ProgressiveVariableList<u8>;

/// Unified read access to the `transactions` of any `ExecutionPayload` variant.
#[derive(Debug)]
pub enum TransactionsRef<'a, E: EthSpec> {
    Bounded(&'a Transactions<E>),
    Progressive(&'a ProgressiveTransactions),
}

impl<E: EthSpec> Clone for TransactionsRef<'_, E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E: EthSpec> Copy for TransactionsRef<'_, E> {}

impl<'a, E: EthSpec> TransactionsRef<'a, E> {
    pub fn len(self) -> usize {
        match self {
            Self::Bounded(transactions) => transactions.len(),
            Self::Progressive(transactions) => transactions.len(),
        }
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Iterate the transactions as byte slices.
    pub fn iter(self) -> TransactionsIter<'a, E> {
        match self {
            Self::Bounded(transactions) => TransactionsIter::Bounded(transactions.iter()),
            Self::Progressive(transactions) => TransactionsIter::Progressive(transactions.iter()),
        }
    }
}

impl<'a, E: EthSpec> From<&'a Transactions<E>> for TransactionsRef<'a, E> {
    fn from(transactions: &'a Transactions<E>) -> Self {
        Self::Bounded(transactions)
    }
}

impl<'a, E: EthSpec> From<&'a ProgressiveTransactions> for TransactionsRef<'a, E> {
    fn from(transactions: &'a ProgressiveTransactions) -> Self {
        Self::Progressive(transactions)
    }
}

impl<'a, E: EthSpec> IntoIterator for TransactionsRef<'a, E> {
    type Item = &'a [u8];
    type IntoIter = TransactionsIter<'a, E>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub enum TransactionsIter<'a, E: EthSpec> {
    Bounded(std::slice::Iter<'a, Transaction<<E as EthSpec>::MaxBytesPerTransaction>>),
    Progressive(std::slice::Iter<'a, ProgressiveVariableList<u8>>),
}

impl<'a, E: EthSpec> Iterator for TransactionsIter<'a, E> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        match self {
            Self::Bounded(iter) => iter.next().map(|transaction| transaction.as_ref()),
            Self::Progressive(iter) => iter.next().map(|transaction| transaction.as_slice()),
        }
    }
}

/// A reference to the withdrawals of any post-Capella `ExecutionPayload` variant.
pub type WithdrawalsRef<'a, E> = ListRef<'a, Withdrawal, <E as EthSpec>::MaxWithdrawalsPerPayload>;

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu, Gloas, Heze),
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
            Educe,
        ),
        context_deserialize(ForkName),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
    ),
    specific_variant_attributes(
        Gloas(tree_hash(
            struct_behaviour = "progressive_container",
            active_fields(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
        )),
        Heze(tree_hash(
            struct_behaviour = "progressive_container",
            active_fields(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
        ))
    ),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec", untagged)]
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
    #[superstruct(
        only(Bellatrix, Capella, Deneb, Electra, Fulu),
        partial_getter(rename = "transactions_bounded")
    )]
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: Transactions<E>,
    #[serde(with = "ssz_types::serde_utils::prog_list_of_hex_prog_var_list")]
    #[superstruct(only(Gloas, Heze), partial_getter(rename = "transactions_progressive"))]
    pub transactions: ProgressiveTransactions,
    #[superstruct(
        only(Capella, Deneb, Electra, Fulu),
        partial_getter(rename = "withdrawals_bounded")
    )]
    pub withdrawals: Withdrawals<E>,
    #[superstruct(only(Gloas, Heze), partial_getter(rename = "withdrawals_progressive"))]
    pub withdrawals: ProgressiveWithdrawals,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas, Heze), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub blob_gas_used: u64,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas, Heze), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub excess_blob_gas: u64,
    /// EIP-7928: Block access list
    #[serde(with = "ssz_types::serde_utils::hex_prog_var_list")]
    #[superstruct(only(Gloas, Heze))]
    pub block_access_list: BlockAccessList,
    #[superstruct(only(Gloas, Heze), partial_getter(copy))]
    pub slot_number: Slot,
}

impl<'a, E: EthSpec> ExecutionPayloadRef<'a, E> {
    // this emulates clone on a normal reference type
    pub fn clone_from_ref(&self) -> ExecutionPayload<E> {
        map_execution_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.clone().into()
        })
    }

    /// Unified access to the `transactions` field across all variants.
    pub fn transactions(self) -> TransactionsRef<'a, E> {
        map_execution_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            TransactionsRef::from(&payload.transactions)
        })
    }

    /// Unified access to the `withdrawals` field (Capella and later).
    pub fn withdrawals(self) -> Result<WithdrawalsRef<'a, E>, BeaconStateError> {
        match self {
            Self::Bellatrix(_) => Err(BeaconStateError::IncorrectStateVariant),
            Self::Capella(payload) => Ok(ListRef::Basic(&payload.withdrawals)),
            Self::Deneb(payload) => Ok(ListRef::Basic(&payload.withdrawals)),
            Self::Electra(payload) => Ok(ListRef::Basic(&payload.withdrawals)),
            Self::Fulu(payload) => Ok(ListRef::Basic(&payload.withdrawals)),
            Self::Gloas(payload) => Ok(ListRef::Progressive(&payload.withdrawals)),
            Self::Heze(payload) => Ok(ListRef::Progressive(&payload.withdrawals)),
        }
    }
}

impl<E: EthSpec> ExecutionPayload<E> {
    /// Unified access to the `transactions` field across all variants.
    pub fn transactions(&self) -> TransactionsRef<'_, E> {
        self.to_ref().transactions()
    }

    /// Unified access to the `withdrawals` field (Capella and later).
    pub fn withdrawals(&self) -> Result<WithdrawalsRef<'_, E>, BeaconStateError> {
        self.to_ref().withdrawals()
    }
}

impl<E: EthSpec> ForkVersionDecode for ExecutionPayload<E> {
    /// SSZ decode with explicit fork variant.
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Base | ForkName::Altair => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionPayload: {fork_name}",
            ))),
            ForkName::Bellatrix => {
                ExecutionPayloadBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => ExecutionPayloadCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => ExecutionPayloadDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
            ForkName::Electra => ExecutionPayloadElectra::from_ssz_bytes(bytes).map(Self::Electra),
            ForkName::Fulu => ExecutionPayloadFulu::from_ssz_bytes(bytes).map(Self::Fulu),
            ForkName::Gloas => ExecutionPayloadGloas::from_ssz_bytes(bytes).map(Self::Gloas),
            ForkName::Heze => ExecutionPayloadHeze::from_ssz_bytes(bytes).map(Self::Heze),
        }
    }
}

impl<E: EthSpec> ExecutionPayload<E> {
    #[allow(clippy::arithmetic_side_effects)]
    /// Returns the maximum size of an execution payload.
    /// TODO(EIP-7732): this seems to only exist for the Bellatrix fork, but Mark's branch has it for all the forks, i.e. max_execution_payload_eip7732_size
    pub fn max_execution_payload_bellatrix_size() -> usize {
        // Fixed part
        ExecutionPayloadBellatrix::<E>::default().as_ssz_bytes().len()
            // Max size of variable length `extra_data` field
            + (E::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
            // Max size of variable length `transactions` field
            + (E::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + E::max_bytes_per_transaction()))
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for ExecutionPayload<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!("ExecutionPayload failed to deserialize: {:?}", e))
        };
        Ok(match context {
            ForkName::Base | ForkName::Altair => {
                return Err(serde::de::Error::custom(format!(
                    "ExecutionPayload failed to deserialize: unsupported fork '{}'",
                    context
                )));
            }
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
            ForkName::Heze => {
                Self::Heze(Deserialize::deserialize(deserializer).map_err(convert_err)?)
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
            ExecutionPayload::Fulu(_) => ForkName::Fulu,
            ExecutionPayload::Gloas(_) => ForkName::Gloas,
            ExecutionPayload::Heze(_) => ForkName::Heze,
        }
    }
}
