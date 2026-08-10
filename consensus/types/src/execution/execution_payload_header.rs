use context_deserialize::{ContextDeserialize, context_deserialize};
use fixed_bytes::FixedBytesExtended;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    core::{Address, ExecutionBlockHash, Hash256, Spec, Uint256},
    execution::{
        ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
        ExecutionPayloadElectra, ExecutionPayloadFulu, ExecutionPayloadRef, Transactions,
    },
    fork::ForkName,
    map_execution_payload_ref_into_execution_payload_header,
    state::BeaconStateError,
};

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu),
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
            PartialEq,
            Hash,
        ),
        serde(deny_unknown_fields),
        cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary),),
        context_deserialize(ForkName),
    ),
    ref_attributes(
        derive(PartialEq, TreeHash, Debug),
        tree_hash(enum_behaviour = "transparent")
    ),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    map_ref_into(ExecutionPayloadHeader)
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, PartialEq, Hash)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct ExecutionPayloadHeader {
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
    pub logs_bloom: FixedVector<u8, typenum::U<{ Spec::BYTES_PER_LOGS_BLOOM }>>,
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
    pub extra_data: VariableList<u8, typenum::U<{ Spec::MAX_EXTRA_DATA_BYTES }>>,
    #[serde(with = "serde_utils::quoted_u256")]
    #[superstruct(getter(copy))]
    pub base_fee_per_gas: Uint256,
    #[superstruct(getter(copy))]
    pub block_hash: ExecutionBlockHash,
    #[superstruct(getter(copy))]
    pub transactions_root: Hash256,
    #[superstruct(only(Capella, Deneb, Electra, Fulu), partial_getter(copy))]
    pub withdrawals_root: Hash256,
    #[superstruct(only(Deneb, Electra, Fulu), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub blob_gas_used: u64,
    #[superstruct(only(Deneb, Electra, Fulu), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub excess_blob_gas: u64,
}

impl ExecutionPayloadHeader {
    pub fn transactions(&self) -> Option<&Transactions> {
        None
    }

    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Base | ForkName::Altair => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionPayloadHeader: {fork_name}",
            ))),
            ForkName::Bellatrix => {
                ExecutionPayloadHeaderBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => {
                ExecutionPayloadHeaderCapella::from_ssz_bytes(bytes).map(Self::Capella)
            }
            ForkName::Deneb => ExecutionPayloadHeaderDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
            ForkName::Electra => {
                ExecutionPayloadHeaderElectra::from_ssz_bytes(bytes).map(Self::Electra)
            }
            ForkName::Fulu => ExecutionPayloadHeaderFulu::from_ssz_bytes(bytes).map(Self::Fulu),
            ForkName::Gloas | ForkName::Heze => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionPayloadHeader: {fork_name}",
            ))),
        }
    }

    #[allow(clippy::arithmetic_side_effects)]
    pub fn ssz_max_var_len_for_fork(fork_name: ForkName) -> usize {
        // TODO(newfork): Add a new case here if there are new variable fields
        if fork_name.gloas_enabled() {
            // TODO(EIP7732) TODO(Heze): check this
            0
        } else if fork_name.bellatrix_enabled() {
            // Max size of variable length `extra_data` field
            Spec::MAX_EXTRA_DATA_BYTES * <u8 as Encode>::ssz_fixed_len()
        } else {
            0
        }
    }

    pub fn fork_name_unchecked(&self) -> ForkName {
        match self {
            ExecutionPayloadHeader::Bellatrix(_) => ForkName::Bellatrix,
            ExecutionPayloadHeader::Capella(_) => ForkName::Capella,
            ExecutionPayloadHeader::Deneb(_) => ForkName::Deneb,
            ExecutionPayloadHeader::Electra(_) => ForkName::Electra,
            ExecutionPayloadHeader::Fulu(_) => ForkName::Fulu,
        }
    }
}

impl<'a> ExecutionPayloadHeaderRef<'a> {
    pub fn is_default_with_zero_roots(self) -> bool {
        map_execution_payload_header_ref!(&'a _, self, |inner, cons| {
            cons(inner);
            *inner == Default::default()
        })
    }
}

impl ExecutionPayloadHeaderBellatrix {
    pub fn upgrade_to_capella(&self) -> ExecutionPayloadHeaderCapella {
        ExecutionPayloadHeaderCapella {
            parent_hash: self.parent_hash,
            fee_recipient: self.fee_recipient,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom.clone(),
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            base_fee_per_gas: self.base_fee_per_gas,
            block_hash: self.block_hash,
            transactions_root: self.transactions_root,
            withdrawals_root: Hash256::zero(),
        }
    }
}

impl ExecutionPayloadHeaderCapella {
    pub fn upgrade_to_deneb(&self) -> ExecutionPayloadHeaderDeneb {
        ExecutionPayloadHeaderDeneb {
            parent_hash: self.parent_hash,
            fee_recipient: self.fee_recipient,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom.clone(),
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            base_fee_per_gas: self.base_fee_per_gas,
            block_hash: self.block_hash,
            transactions_root: self.transactions_root,
            withdrawals_root: self.withdrawals_root,
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }
}

impl ExecutionPayloadHeaderDeneb {
    pub fn upgrade_to_electra(&self) -> ExecutionPayloadHeaderElectra {
        ExecutionPayloadHeaderElectra {
            parent_hash: self.parent_hash,
            fee_recipient: self.fee_recipient,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom.clone(),
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            base_fee_per_gas: self.base_fee_per_gas,
            block_hash: self.block_hash,
            transactions_root: self.transactions_root,
            withdrawals_root: self.withdrawals_root,
            blob_gas_used: self.blob_gas_used,
            excess_blob_gas: self.excess_blob_gas,
        }
    }
}

impl ExecutionPayloadHeaderElectra {
    pub fn upgrade_to_fulu(&self) -> ExecutionPayloadHeaderFulu {
        ExecutionPayloadHeaderFulu {
            parent_hash: self.parent_hash,
            fee_recipient: self.fee_recipient,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom.clone(),
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            base_fee_per_gas: self.base_fee_per_gas,
            block_hash: self.block_hash,
            transactions_root: self.transactions_root,
            withdrawals_root: self.withdrawals_root,
            blob_gas_used: self.blob_gas_used,
            excess_blob_gas: self.excess_blob_gas,
        }
    }
}

impl<'a> From<&'a ExecutionPayloadBellatrix> for ExecutionPayloadHeaderBellatrix {
    fn from(payload: &'a ExecutionPayloadBellatrix) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.tree_hash_root(),
        }
    }
}

impl<'a> From<&'a ExecutionPayloadCapella> for ExecutionPayloadHeaderCapella {
    fn from(payload: &'a ExecutionPayloadCapella) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.tree_hash_root(),
            withdrawals_root: payload.withdrawals.tree_hash_root(),
        }
    }
}

impl<'a> From<&'a ExecutionPayloadDeneb> for ExecutionPayloadHeaderDeneb {
    fn from(payload: &'a ExecutionPayloadDeneb) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.tree_hash_root(),
            withdrawals_root: payload.withdrawals.tree_hash_root(),
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
        }
    }
}

impl<'a> From<&'a ExecutionPayloadElectra> for ExecutionPayloadHeaderElectra {
    fn from(payload: &'a ExecutionPayloadElectra) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.tree_hash_root(),
            withdrawals_root: payload.withdrawals.tree_hash_root(),
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
        }
    }
}

impl<'a> From<&'a ExecutionPayloadFulu> for ExecutionPayloadHeaderFulu {
    fn from(payload: &'a ExecutionPayloadFulu) -> Self {
        Self {
            parent_hash: payload.parent_hash,
            fee_recipient: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom.clone(),
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.clone(),
            base_fee_per_gas: payload.base_fee_per_gas,
            block_hash: payload.block_hash,
            transactions_root: payload.transactions.tree_hash_root(),
            withdrawals_root: payload.withdrawals.tree_hash_root(),
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
        }
    }
}

// These impls are required to work around an inelegance in `to_execution_payload_header`.
// They only clone headers so they should be relatively cheap.
impl<'a> From<&'a Self> for ExecutionPayloadHeaderBellatrix {
    fn from(payload: &'a Self) -> Self {
        payload.clone()
    }
}

impl<'a> From<&'a Self> for ExecutionPayloadHeaderCapella {
    fn from(payload: &'a Self) -> Self {
        payload.clone()
    }
}

impl<'a> From<&'a Self> for ExecutionPayloadHeaderDeneb {
    fn from(payload: &'a Self) -> Self {
        payload.clone()
    }
}

impl<'a> From<&'a Self> for ExecutionPayloadHeaderElectra {
    fn from(payload: &'a Self) -> Self {
        payload.clone()
    }
}

impl<'a> From<&'a Self> for ExecutionPayloadHeaderFulu {
    fn from(payload: &'a Self) -> Self {
        payload.clone()
    }
}

impl<'a> From<ExecutionPayloadRef<'a>> for ExecutionPayloadHeader {
    fn from(payload: ExecutionPayloadRef<'a>) -> Self {
        map_execution_payload_ref_into_execution_payload_header!(
            &'a _,
            payload,
            |inner, cons| cons(inner.into())
        )
    }
}

impl TryFrom<ExecutionPayloadHeader> for ExecutionPayloadHeaderBellatrix {
    type Error = BeaconStateError;
    fn try_from(header: ExecutionPayloadHeader) -> Result<Self, Self::Error> {
        match header {
            ExecutionPayloadHeader::Bellatrix(execution_payload_header) => {
                Ok(execution_payload_header)
            }
            _ => Err(BeaconStateError::IncorrectStateVariant),
        }
    }
}
impl TryFrom<ExecutionPayloadHeader> for ExecutionPayloadHeaderCapella {
    type Error = BeaconStateError;
    fn try_from(header: ExecutionPayloadHeader) -> Result<Self, Self::Error> {
        match header {
            ExecutionPayloadHeader::Capella(execution_payload_header) => {
                Ok(execution_payload_header)
            }
            _ => Err(BeaconStateError::IncorrectStateVariant),
        }
    }
}
impl TryFrom<ExecutionPayloadHeader> for ExecutionPayloadHeaderDeneb {
    type Error = BeaconStateError;
    fn try_from(header: ExecutionPayloadHeader) -> Result<Self, Self::Error> {
        match header {
            ExecutionPayloadHeader::Deneb(execution_payload_header) => Ok(execution_payload_header),
            _ => Err(BeaconStateError::IncorrectStateVariant),
        }
    }
}

impl ExecutionPayloadHeaderRefMut<'_> {
    /// Mutate through
    pub fn replace(self, header: ExecutionPayloadHeader) -> Result<(), BeaconStateError> {
        match self {
            ExecutionPayloadHeaderRefMut::Bellatrix(mut_ref) => {
                *mut_ref = header.try_into()?;
            }
            ExecutionPayloadHeaderRefMut::Capella(mut_ref) => {
                *mut_ref = header.try_into()?;
            }
            ExecutionPayloadHeaderRefMut::Deneb(mut_ref) => {
                *mut_ref = header.try_into()?;
            }
            ExecutionPayloadHeaderRefMut::Electra(mut_ref) => {
                *mut_ref = header.try_into()?;
            }
            ExecutionPayloadHeaderRefMut::Fulu(mut_ref) => {
                *mut_ref = header.try_into()?;
            }
        }
        Ok(())
    }
}

impl TryFrom<ExecutionPayloadHeader> for ExecutionPayloadHeaderElectra {
    type Error = BeaconStateError;
    fn try_from(header: ExecutionPayloadHeader) -> Result<Self, Self::Error> {
        match header {
            ExecutionPayloadHeader::Electra(execution_payload_header) => {
                Ok(execution_payload_header)
            }
            _ => Err(BeaconStateError::IncorrectStateVariant),
        }
    }
}

impl TryFrom<ExecutionPayloadHeader> for ExecutionPayloadHeaderFulu {
    type Error = BeaconStateError;
    fn try_from(header: ExecutionPayloadHeader) -> Result<Self, Self::Error> {
        match header {
            ExecutionPayloadHeader::Fulu(execution_payload_header) => Ok(execution_payload_header),
            _ => Err(BeaconStateError::IncorrectStateVariant),
        }
    }
}

impl<'de> ContextDeserialize<'de, ForkName> for ExecutionPayloadHeader {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!(
                "ExecutionPayloadHeader failed to deserialize: {:?}",
                e
            ))
        };
        Ok(match context {
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

            ForkName::Base | ForkName::Altair | ForkName::Gloas | ForkName::Heze => {
                return Err(serde::de::Error::custom(format!(
                    "ExecutionPayloadHeader failed to deserialize: unsupported fork '{}'",
                    context
                )));
            }
        })
    }
}
