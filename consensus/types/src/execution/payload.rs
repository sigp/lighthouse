use educe::Educe;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::{borrow::Cow, fmt::Debug, hash::Hash};
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use typenum::U;

use crate::{
    core::{Address, ExecutionBlockHash, Hash256, Spec},
    execution::{
        ExecutionPayload, ExecutionPayloadBellatrix, ExecutionPayloadCapella,
        ExecutionPayloadDeneb, ExecutionPayloadElectra, ExecutionPayloadFulu,
        ExecutionPayloadHeader, ExecutionPayloadHeaderBellatrix, ExecutionPayloadHeaderCapella,
        ExecutionPayloadHeaderDeneb, ExecutionPayloadHeaderElectra, ExecutionPayloadHeaderFulu,
        ExecutionPayloadRef, Transactions,
    },
    fork::ForkName,
    map_execution_payload_into_blinded_payload, map_execution_payload_into_full_payload,
    state::BeaconStateError,
};

#[derive(Debug, PartialEq)]
pub enum BlockType {
    Blinded,
    Full,
}

/// A trait representing behavior of an `ExecutionPayload` that either has a full list of transactions
/// or a transaction hash in it's place.
pub trait ExecPayload: Debug + Clone + PartialEq + Hash + TreeHash + Send {
    fn block_type() -> BlockType;

    /// Convert the payload into a payload header.
    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader;

    /// We provide a subset of field accessors, for the fields used in `consensus`.
    ///
    /// More fields can be added here if you wish.
    fn parent_hash(&self) -> ExecutionBlockHash;
    fn prev_randao(&self) -> Hash256;
    fn block_number(&self) -> u64;
    fn timestamp(&self) -> u64;
    fn extra_data(&self) -> VariableList<u8, U<{ Spec::MAX_EXTRA_DATA_BYTES }>>;
    fn block_hash(&self) -> ExecutionBlockHash;
    fn fee_recipient(&self) -> Address;
    fn gas_limit(&self) -> u64;
    fn transactions(&self) -> Option<&Transactions>;
    /// fork-specific fields
    fn withdrawals_root(&self) -> Result<Hash256, BeaconStateError>;
    fn blob_gas_used(&self) -> Result<u64, BeaconStateError>;

    /// Is this a default payload with 0x0 roots for transactions and withdrawals?
    fn is_default_with_zero_roots(&self) -> bool;

    /// Is this a default payload with the hash of the empty list for transactions and withdrawals?
    fn is_default_with_empty_roots(&self) -> bool;
}

/// `ExecPayload` functionality the requires ownership.
#[cfg(feature = "arbitrary")]
pub trait OwnedExecPayload:
    ExecPayload
    + Default
    + Serialize
    + DeserializeOwned
    + Encode
    + Decode
    + for<'a> arbitrary::Arbitrary<'a>
    + 'static
{
}
#[cfg(feature = "arbitrary")]
impl<P> OwnedExecPayload for P where
    P: ExecPayload
        + Default
        + Serialize
        + DeserializeOwned
        + Encode
        + Decode
        + for<'a> arbitrary::Arbitrary<'a>
        + 'static
{
}

/// `ExecPayload` functionality the requires ownership.
#[cfg(not(feature = "arbitrary"))]
pub trait OwnedExecPayload:
    ExecPayload + Default + Serialize + DeserializeOwned + Encode + Decode + 'static
{
}
#[cfg(not(feature = "arbitrary"))]
impl<P> OwnedExecPayload for P where
    P: ExecPayload + Default + Serialize + DeserializeOwned + Encode + Decode + 'static
{
}

pub trait AbstractExecPayload:
    ExecPayload
    + Sized
    + From<ExecutionPayload>
    + TryFrom<ExecutionPayloadHeader>
    + TryInto<Self::Bellatrix>
    + TryInto<Self::Capella>
    + TryInto<Self::Deneb>
    + TryInto<Self::Electra>
    + TryInto<Self::Fulu>
    + Sync
{
    type Ref<'a>: ExecPayload
        + Copy
        + From<&'a Self::Bellatrix>
        + From<&'a Self::Capella>
        + From<&'a Self::Deneb>
        + From<&'a Self::Electra>
        + From<&'a Self::Fulu>;

    type Bellatrix: OwnedExecPayload
        + Into<Self>
        + for<'a> From<Cow<'a, ExecutionPayloadBellatrix>>
        + TryFrom<ExecutionPayloadHeaderBellatrix>
        + Sync;
    type Capella: OwnedExecPayload
        + Into<Self>
        + for<'a> From<Cow<'a, ExecutionPayloadCapella>>
        + TryFrom<ExecutionPayloadHeaderCapella>
        + Sync;
    type Deneb: OwnedExecPayload
        + Into<Self>
        + for<'a> From<Cow<'a, ExecutionPayloadDeneb>>
        + TryFrom<ExecutionPayloadHeaderDeneb>
        + Sync;
    type Electra: OwnedExecPayload
        + Into<Self>
        + for<'a> From<Cow<'a, ExecutionPayloadElectra>>
        + TryFrom<ExecutionPayloadHeaderElectra>
        + Sync;
    type Fulu: OwnedExecPayload
        + Into<Self>
        + for<'a> From<Cow<'a, ExecutionPayloadFulu>>
        + TryFrom<ExecutionPayloadHeaderFulu>
        + Sync;
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu),
    variant_attributes(
        derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Educe,),
        educe(PartialEq, Hash),
        serde(deny_unknown_fields),
        cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary),),
        ssz(struct_behaviour = "transparent"),
    ),
    ref_attributes(
        derive(Debug, Educe, TreeHash),
        educe(PartialEq, Hash),
        tree_hash(enum_behaviour = "transparent"),
    ),
    map_into(ExecutionPayload),
    map_ref_into(ExecutionPayloadRef),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Deserialize, TreeHash, Educe)]
#[educe(PartialEq, Hash)]
#[tree_hash(enum_behaviour = "transparent")]
pub struct FullPayload {
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "execution_payload_bellatrix")
    )]
    pub execution_payload: ExecutionPayloadBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: ExecutionPayloadDeneb,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    pub execution_payload: ExecutionPayloadElectra,
    #[superstruct(only(Fulu), partial_getter(rename = "execution_payload_fulu"))]
    pub execution_payload: ExecutionPayloadFulu,
}

impl From<FullPayload> for ExecutionPayload {
    fn from(full_payload: FullPayload) -> Self {
        map_full_payload_into_execution_payload!(full_payload, move |payload, cons| {
            cons(payload.execution_payload)
        })
    }
}

impl<'a> From<FullPayloadRef<'a>> for ExecutionPayload {
    fn from(full_payload_ref: FullPayloadRef<'a>) -> Self {
        map_full_payload_ref!(&'a _, full_payload_ref, move |payload, cons| {
            cons(payload);
            payload.execution_payload.clone().into()
        })
    }
}

impl<'a> From<FullPayloadRef<'a>> for FullPayload {
    fn from(full_payload_ref: FullPayloadRef<'a>) -> Self {
        map_full_payload_ref!(&'a _, full_payload_ref, move |payload, cons| {
            cons(payload);
            payload.clone().into()
        })
    }
}

impl ExecPayload for FullPayload {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header<'a>(&'a self) -> ExecutionPayloadHeader {
        map_full_payload_ref!(&'a _, self.to_ref(), move |inner, cons| {
            cons(inner);
            let exec_payload_ref: ExecutionPayloadRef<'a> = From::from(&inner.execution_payload);
            ExecutionPayloadHeader::from(exec_payload_ref)
        })
    }

    fn parent_hash<'a>(&'a self) -> ExecutionBlockHash {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload.parent_hash
        })
    }

    fn prev_randao<'a>(&'a self) -> Hash256 {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload.prev_randao
        })
    }

    fn block_number<'a>(&'a self) -> u64 {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload.block_number
        })
    }

    fn timestamp<'a>(&'a self) -> u64 {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload.timestamp
        })
    }

    fn extra_data<'a>(&'a self) -> VariableList<u8, U<{ Spec::MAX_EXTRA_DATA_BYTES }>> {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload.extra_data.clone()
        })
    }

    fn block_hash<'a>(&'a self) -> ExecutionBlockHash {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload.block_hash
        })
    }

    fn fee_recipient<'a>(&'a self) -> Address {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload.fee_recipient
        })
    }

    fn gas_limit<'a>(&'a self) -> u64 {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload.gas_limit
        })
    }

    fn transactions<'a>(&'a self) -> Option<&'a Transactions> {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            Some(&payload.execution_payload.transactions)
        })
    }

    fn withdrawals_root(&self) -> Result<Hash256, BeaconStateError> {
        match self {
            FullPayload::Bellatrix(_) => Err(BeaconStateError::IncorrectStateVariant),
            FullPayload::Capella(inner) => Ok(inner.execution_payload.withdrawals.tree_hash_root()),
            FullPayload::Deneb(inner) => Ok(inner.execution_payload.withdrawals.tree_hash_root()),
            FullPayload::Electra(inner) => Ok(inner.execution_payload.withdrawals.tree_hash_root()),
            FullPayload::Fulu(inner) => Ok(inner.execution_payload.withdrawals.tree_hash_root()),
        }
    }

    fn blob_gas_used(&self) -> Result<u64, BeaconStateError> {
        match self {
            FullPayload::Bellatrix(_) | FullPayload::Capella(_) => {
                Err(BeaconStateError::IncorrectStateVariant)
            }
            FullPayload::Deneb(inner) => Ok(inner.execution_payload.blob_gas_used),
            FullPayload::Electra(inner) => Ok(inner.execution_payload.blob_gas_used),
            FullPayload::Fulu(inner) => Ok(inner.execution_payload.blob_gas_used),
        }
    }

    fn is_default_with_zero_roots<'a>(&'a self) -> bool {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload == <_>::default()
        })
    }

    fn is_default_with_empty_roots(&self) -> bool {
        // For full payloads the empty/zero distinction does not exist.
        self.is_default_with_zero_roots()
    }
}

impl FullPayload {
    pub fn execution_payload(self) -> ExecutionPayload {
        map_full_payload_into_execution_payload!(self, |inner, cons| {
            cons(inner.execution_payload)
        })
    }

    pub fn default_at_fork(fork_name: ForkName) -> Result<Self, BeaconStateError> {
        match fork_name {
            ForkName::Base | ForkName::Altair => Err(BeaconStateError::IncorrectStateVariant),
            ForkName::Bellatrix => Ok(FullPayloadBellatrix::default().into()),
            ForkName::Capella => Ok(FullPayloadCapella::default().into()),
            ForkName::Deneb => Ok(FullPayloadDeneb::default().into()),
            ForkName::Electra => Ok(FullPayloadElectra::default().into()),
            ForkName::Fulu => Ok(FullPayloadFulu::default().into()),
            ForkName::Gloas | ForkName::Heze => Err(BeaconStateError::IncorrectStateVariant),
        }
    }
}

impl<'a> FullPayloadRef<'a> {
    pub fn execution_payload_ref(self) -> ExecutionPayloadRef<'a> {
        map_full_payload_ref_into_execution_payload_ref!(&'a _, self, |inner, cons| {
            cons(&inner.execution_payload)
        })
    }
}

impl ExecPayload for FullPayloadRef<'_> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header<'a>(&'a self) -> ExecutionPayloadHeader {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.to_execution_payload_header()
        })
    }

    fn parent_hash<'a>(&'a self) -> ExecutionBlockHash {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload.parent_hash
        })
    }

    fn prev_randao<'a>(&'a self) -> Hash256 {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload.prev_randao
        })
    }

    fn block_number<'a>(&'a self) -> u64 {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload.block_number
        })
    }

    fn timestamp<'a>(&'a self) -> u64 {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload.timestamp
        })
    }

    fn extra_data<'a>(&'a self) -> VariableList<u8, U<{ Spec::MAX_EXTRA_DATA_BYTES }>> {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload.extra_data.clone()
        })
    }

    fn block_hash<'a>(&'a self) -> ExecutionBlockHash {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload.block_hash
        })
    }

    fn fee_recipient<'a>(&'a self) -> Address {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload.fee_recipient
        })
    }

    fn gas_limit<'a>(&'a self) -> u64 {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload.gas_limit
        })
    }

    fn transactions<'a>(&'a self) -> Option<&'a Transactions> {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            Some(&payload.execution_payload.transactions)
        })
    }

    fn withdrawals_root(&self) -> Result<Hash256, BeaconStateError> {
        match self {
            FullPayloadRef::Bellatrix(_) => Err(BeaconStateError::IncorrectStateVariant),
            FullPayloadRef::Capella(inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
            FullPayloadRef::Deneb(inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
            FullPayloadRef::Electra(inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
            FullPayloadRef::Fulu(inner) => Ok(inner.execution_payload.withdrawals.tree_hash_root()),
        }
    }

    fn blob_gas_used(&self) -> Result<u64, BeaconStateError> {
        match self {
            FullPayloadRef::Bellatrix(_) | FullPayloadRef::Capella(_) => {
                Err(BeaconStateError::IncorrectStateVariant)
            }
            FullPayloadRef::Deneb(inner) => Ok(inner.execution_payload.blob_gas_used),
            FullPayloadRef::Electra(inner) => Ok(inner.execution_payload.blob_gas_used),
            FullPayloadRef::Fulu(inner) => Ok(inner.execution_payload.blob_gas_used),
        }
    }

    fn is_default_with_zero_roots<'a>(&'a self) -> bool {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload == <_>::default()
        })
    }

    fn is_default_with_empty_roots(&self) -> bool {
        // For full payloads the empty/zero distinction does not exist.
        self.is_default_with_zero_roots()
    }
}

impl AbstractExecPayload for FullPayload {
    type Ref<'a> = FullPayloadRef<'a>;
    type Bellatrix = FullPayloadBellatrix;
    type Capella = FullPayloadCapella;
    type Deneb = FullPayloadDeneb;
    type Electra = FullPayloadElectra;
    type Fulu = FullPayloadFulu;
}

impl From<ExecutionPayload> for FullPayload {
    fn from(execution_payload: ExecutionPayload) -> Self {
        map_execution_payload_into_full_payload!(execution_payload, |inner, cons| {
            cons(inner.into())
        })
    }
}

impl TryFrom<ExecutionPayloadHeader> for FullPayload {
    type Error = ();
    fn try_from(_: ExecutionPayloadHeader) -> Result<Self, Self::Error> {
        Err(())
    }
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu),
    variant_attributes(
        derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, Educe,),
        educe(PartialEq, Hash),
        serde(deny_unknown_fields),
        cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary),),
        ssz(struct_behaviour = "transparent"),
    ),
    ref_attributes(
        derive(Debug, Educe, TreeHash),
        educe(PartialEq, Hash),
        tree_hash(enum_behaviour = "transparent"),
    ),
    map_into(ExecutionPayloadHeader),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Serialize, Deserialize, TreeHash, Educe)]
#[educe(PartialEq, Hash)]
#[tree_hash(enum_behaviour = "transparent")]
pub struct BlindedPayload {
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "execution_payload_bellatrix")
    )]
    pub execution_payload_header: ExecutionPayloadHeaderBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload_header: ExecutionPayloadHeaderCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload_header: ExecutionPayloadHeaderDeneb,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    pub execution_payload_header: ExecutionPayloadHeaderElectra,
    #[superstruct(only(Fulu), partial_getter(rename = "execution_payload_fulu"))]
    pub execution_payload_header: ExecutionPayloadHeaderFulu,
}

impl<'a> From<BlindedPayloadRef<'a>> for BlindedPayload {
    fn from(blinded_payload_ref: BlindedPayloadRef<'a>) -> Self {
        map_blinded_payload_ref!(&'a _, blinded_payload_ref, move |payload, cons| {
            cons(payload);
            payload.clone().into()
        })
    }
}

impl ExecPayload for BlindedPayload {
    fn block_type() -> BlockType {
        BlockType::Blinded
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader {
        map_blinded_payload_into_execution_payload_header!(self.clone(), |inner, cons| {
            cons(inner.execution_payload_header)
        })
    }

    fn parent_hash<'a>(&'a self) -> ExecutionBlockHash {
        map_blinded_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.parent_hash
        })
    }

    fn prev_randao<'a>(&'a self) -> Hash256 {
        map_blinded_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.prev_randao
        })
    }

    fn block_number<'a>(&'a self) -> u64 {
        map_blinded_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.block_number
        })
    }

    fn timestamp<'a>(&'a self) -> u64 {
        map_blinded_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.timestamp
        })
    }

    fn extra_data<'a>(&'a self) -> VariableList<u8, U<{ Spec::MAX_EXTRA_DATA_BYTES }>> {
        map_blinded_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.extra_data.clone()
        })
    }

    fn block_hash<'a>(&'a self) -> ExecutionBlockHash {
        map_blinded_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.block_hash
        })
    }

    fn fee_recipient<'a>(&'a self) -> Address {
        map_blinded_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.fee_recipient
        })
    }

    fn gas_limit<'a>(&'a self) -> u64 {
        map_blinded_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.gas_limit
        })
    }

    fn transactions(&self) -> Option<&Transactions> {
        None
    }

    fn withdrawals_root(&self) -> Result<Hash256, BeaconStateError> {
        match self {
            BlindedPayload::Bellatrix(_) => Err(BeaconStateError::IncorrectStateVariant),
            BlindedPayload::Capella(inner) => Ok(inner.execution_payload_header.withdrawals_root),
            BlindedPayload::Deneb(inner) => Ok(inner.execution_payload_header.withdrawals_root),
            BlindedPayload::Electra(inner) => Ok(inner.execution_payload_header.withdrawals_root),
            BlindedPayload::Fulu(inner) => Ok(inner.execution_payload_header.withdrawals_root),
        }
    }

    fn blob_gas_used(&self) -> Result<u64, BeaconStateError> {
        match self {
            BlindedPayload::Bellatrix(_) | BlindedPayload::Capella(_) => {
                Err(BeaconStateError::IncorrectStateVariant)
            }
            BlindedPayload::Deneb(inner) => Ok(inner.execution_payload_header.blob_gas_used),
            BlindedPayload::Electra(inner) => Ok(inner.execution_payload_header.blob_gas_used),
            BlindedPayload::Fulu(inner) => Ok(inner.execution_payload_header.blob_gas_used),
        }
    }

    fn is_default_with_zero_roots(&self) -> bool {
        self.to_ref().is_default_with_zero_roots()
    }

    // For blinded payloads we must check "defaultness" against the default `ExecutionPayload`
    // which has been blinded into an `ExecutionPayloadHeader`, NOT against the default
    // `ExecutionPayloadHeader` which has a zeroed out `transactions_root`. The transactions root
    // should be the root of the empty list.
    fn is_default_with_empty_roots(&self) -> bool {
        self.to_ref().is_default_with_empty_roots()
    }
}

impl<'b> ExecPayload for BlindedPayloadRef<'b> {
    fn block_type() -> BlockType {
        BlockType::Blinded
    }

    fn to_execution_payload_header<'a>(&'a self) -> ExecutionPayloadHeader {
        map_blinded_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.to_execution_payload_header()
        })
    }

    fn parent_hash<'a>(&'a self) -> ExecutionBlockHash {
        map_blinded_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.parent_hash
        })
    }

    fn prev_randao<'a>(&'a self) -> Hash256 {
        map_blinded_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.prev_randao
        })
    }

    fn block_number<'a>(&'a self) -> u64 {
        map_blinded_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.block_number
        })
    }

    fn timestamp<'a>(&'a self) -> u64 {
        map_blinded_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.timestamp
        })
    }

    fn extra_data<'a>(&'a self) -> VariableList<u8, U<{ Spec::MAX_EXTRA_DATA_BYTES }>> {
        map_blinded_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.extra_data.clone()
        })
    }

    fn block_hash<'a>(&'a self) -> ExecutionBlockHash {
        map_blinded_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.block_hash
        })
    }

    fn fee_recipient<'a>(&'a self) -> Address {
        map_blinded_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.fee_recipient
        })
    }

    fn gas_limit<'a>(&'a self) -> u64 {
        map_blinded_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload_header.gas_limit
        })
    }

    fn transactions(&self) -> Option<&Transactions> {
        None
    }

    fn withdrawals_root(&self) -> Result<Hash256, BeaconStateError> {
        match self {
            BlindedPayloadRef::Bellatrix(_) => Err(BeaconStateError::IncorrectStateVariant),
            BlindedPayloadRef::Capella(inner) => {
                Ok(inner.execution_payload_header.withdrawals_root)
            }
            BlindedPayloadRef::Deneb(inner) => Ok(inner.execution_payload_header.withdrawals_root),
            BlindedPayloadRef::Electra(inner) => {
                Ok(inner.execution_payload_header.withdrawals_root)
            }
            BlindedPayloadRef::Fulu(inner) => Ok(inner.execution_payload_header.withdrawals_root),
        }
    }

    fn blob_gas_used(&self) -> Result<u64, BeaconStateError> {
        match self {
            BlindedPayloadRef::Bellatrix(_) | BlindedPayloadRef::Capella(_) => {
                Err(BeaconStateError::IncorrectStateVariant)
            }
            BlindedPayloadRef::Deneb(inner) => Ok(inner.execution_payload_header.blob_gas_used),
            BlindedPayloadRef::Electra(inner) => Ok(inner.execution_payload_header.blob_gas_used),
            BlindedPayloadRef::Fulu(inner) => Ok(inner.execution_payload_header.blob_gas_used),
        }
    }

    fn is_default_with_zero_roots<'a>(&'a self) -> bool {
        map_blinded_payload_ref!(&'b _, self, move |payload, cons| {
            cons(payload);
            payload.execution_payload_header == <_>::default()
        })
    }

    fn is_default_with_empty_roots<'a>(&'a self) -> bool {
        map_blinded_payload_ref!(&'b _, self, move |payload, cons| {
            cons(payload);
            payload.is_default_with_empty_roots()
        })
    }
}

macro_rules! impl_exec_payload_common {
    ($wrapper_type:ident,           // BlindedPayloadBellatrix          |   FullPayloadBellatrix
     $wrapped_type:ident,           // ExecutionPayloadHeaderBellatrix  |   ExecutionPayloadBellatrix
     $wrapped_type_full:ident,      // ExecutionPayloadBellatrix        |   ExecutionPayloadBellatrix
     $wrapped_type_header:ident,    // ExecutionPayloadHeaderBellatrix  |   ExecutionPayloadHeaderBellatrix
     $wrapped_field:ident,          // execution_payload_header     |   execution_payload
     $fork_variant:ident,           // Bellatrix                    |   Bellatrix
     $block_type_variant:ident,     // Blinded                      |   Full
     $is_default_with_empty_roots:block,
     $f:block,
     $g:block,
     $h:block) => {
        impl ExecPayload for $wrapper_type {
            fn block_type() -> BlockType {
                BlockType::$block_type_variant
            }

            fn to_execution_payload_header(&self) -> ExecutionPayloadHeader {
                ExecutionPayloadHeader::$fork_variant($wrapped_type_header::from(
                    &self.$wrapped_field,
                ))
            }

            fn parent_hash(&self) -> ExecutionBlockHash {
                self.$wrapped_field.parent_hash
            }

            fn prev_randao(&self) -> Hash256 {
                self.$wrapped_field.prev_randao
            }

            fn block_number(&self) -> u64 {
                self.$wrapped_field.block_number
            }

            fn timestamp(&self) -> u64 {
                self.$wrapped_field.timestamp
            }

            fn extra_data(&self) -> VariableList<u8, U<{ Spec::MAX_EXTRA_DATA_BYTES }>> {
                self.$wrapped_field.extra_data.clone()
            }

            fn block_hash(&self) -> ExecutionBlockHash {
                self.$wrapped_field.block_hash
            }

            fn fee_recipient(&self) -> Address {
                self.$wrapped_field.fee_recipient
            }

            fn gas_limit(&self) -> u64 {
                self.$wrapped_field.gas_limit
            }

            fn is_default_with_zero_roots(&self) -> bool {
                self.$wrapped_field == $wrapped_type::default()
            }

            fn is_default_with_empty_roots(&self) -> bool {
                let f = $is_default_with_empty_roots;
                f(self)
            }

            fn transactions(&self) -> Option<&Transactions> {
                let f = $f;
                f(self)
            }

            fn withdrawals_root(&self) -> Result<Hash256, BeaconStateError> {
                let g = $g;
                g(self)
            }

            fn blob_gas_used(&self) -> Result<u64, BeaconStateError> {
                let h = $h;
                h(self)
            }
        }

        impl From<$wrapped_type> for $wrapper_type {
            fn from($wrapped_field: $wrapped_type) -> Self {
                Self { $wrapped_field }
            }
        }
    };
}

macro_rules! impl_exec_payload_for_fork {
    // BlindedPayloadBellatrix, FullPayloadBellatrix, ExecutionPayloadHeaderBellatrix, ExecutionPayloadBellatrix, Bellatrix
    ($wrapper_type_header:ident, $wrapper_type_full:ident, $wrapped_type_header:ident, $wrapped_type_full:ident, $fork_variant:ident) => {
        //*************** Blinded payload implementations ******************//

        impl_exec_payload_common!(
            $wrapper_type_header, // BlindedPayloadBellatrix
            $wrapped_type_header, // ExecutionPayloadHeaderBellatrix
            $wrapped_type_full,   // ExecutionPayloadBellatrix
            $wrapped_type_header, // ExecutionPayloadHeaderBellatrix
            execution_payload_header,
            $fork_variant, // Bellatrix
            Blinded,
            {
                |wrapper: &$wrapper_type_header| {
                    wrapper.execution_payload_header
                        == $wrapped_type_header::from(&$wrapped_type_full::default())
                }
            },
            { |_| { None } },
            {
                let c: for<'a> fn(&'a $wrapper_type_header) -> Result<Hash256, BeaconStateError> =
                    |payload: &$wrapper_type_header| {
                        let wrapper_ref_type = BlindedPayloadRef::$fork_variant(&payload);
                        wrapper_ref_type.withdrawals_root()
                    };
                c
            },
            {
                let c: for<'a> fn(&'a $wrapper_type_header) -> Result<u64, BeaconStateError> =
                    |payload: &$wrapper_type_header| {
                        let wrapper_ref_type = BlindedPayloadRef::$fork_variant(&payload);
                        wrapper_ref_type.blob_gas_used()
                    };
                c
            }
        );

        impl TryInto<$wrapper_type_header> for BlindedPayload {
            type Error = BeaconStateError;

            fn try_into(self) -> Result<$wrapper_type_header, Self::Error> {
                match self {
                    BlindedPayload::$fork_variant(payload) => Ok(payload),
                    _ => Err(BeaconStateError::IncorrectStateVariant),
                }
            }
        }

        // NOTE: the `Default` implementation for `BlindedPayload` needs to be different from the `Default`
        // implementation for `ExecutionPayloadHeader` because payloads are checked for equality against the
        // default payload in `is_merge_transition_block` to determine whether the merge has occurred.
        //
        // The default `BlindedPayload` is therefore the payload header that results from blinding the
        // default `ExecutionPayload`, which differs from the default `ExecutionPayloadHeader` in that
        // its `transactions_root` is the hash of the empty list rather than 0x0.
        impl Default for $wrapper_type_header {
            fn default() -> Self {
                Self {
                    execution_payload_header: $wrapped_type_header::from(
                        &$wrapped_type_full::default(),
                    ),
                }
            }
        }

        impl TryFrom<ExecutionPayloadHeader> for $wrapper_type_header {
            type Error = BeaconStateError;
            fn try_from(header: ExecutionPayloadHeader) -> Result<Self, Self::Error> {
                match header {
                    ExecutionPayloadHeader::$fork_variant(execution_payload_header) => {
                        Ok(execution_payload_header.into())
                    }
                    _ => Err(BeaconStateError::PayloadConversionLogicFlaw),
                }
            }
        }

        // BlindedPayload* from CoW reference to ExecutionPayload* (hopefully just a reference).
        impl<'a> From<Cow<'a, $wrapped_type_full>> for $wrapper_type_header {
            fn from(execution_payload: Cow<'a, $wrapped_type_full>) -> Self {
                Self {
                    execution_payload_header: $wrapped_type_header::from(&*execution_payload),
                }
            }
        }

        //*************** Full payload implementations ******************//

        impl_exec_payload_common!(
            $wrapper_type_full,   // FullPayloadBellatrix
            $wrapped_type_full,   // ExecutionPayloadBellatrix
            $wrapped_type_full,   // ExecutionPayloadBellatrix
            $wrapped_type_header, // ExecutionPayloadHeaderBellatrix
            execution_payload,
            $fork_variant, // Bellatrix
            Full,
            {
                |wrapper: &$wrapper_type_full| {
                    wrapper.execution_payload == $wrapped_type_full::default()
                }
            },
            {
                let c: for<'a> fn(&'a $wrapper_type_full) -> Option<&'a Transactions> =
                    |payload: &$wrapper_type_full| Some(&payload.execution_payload.transactions);
                c
            },
            {
                let c: for<'a> fn(&'a $wrapper_type_full) -> Result<Hash256, BeaconStateError> =
                    |payload: &$wrapper_type_full| {
                        let wrapper_ref_type = FullPayloadRef::$fork_variant(&payload);
                        wrapper_ref_type.withdrawals_root()
                    };
                c
            },
            {
                let c: for<'a> fn(&'a $wrapper_type_full) -> Result<u64, BeaconStateError> =
                    |payload: &$wrapper_type_full| {
                        let wrapper_ref_type = FullPayloadRef::$fork_variant(&payload);
                        wrapper_ref_type.blob_gas_used()
                    };
                c
            }
        );

        impl Default for $wrapper_type_full {
            fn default() -> Self {
                Self {
                    execution_payload: $wrapped_type_full::default(),
                }
            }
        }

        // FullPayload * from CoW reference to ExecutionPayload* (hopefully already owned).
        impl<'a> From<Cow<'a, $wrapped_type_full>> for $wrapper_type_full {
            fn from(execution_payload: Cow<'a, $wrapped_type_full>) -> Self {
                Self {
                    execution_payload: $wrapped_type_full::from(execution_payload.into_owned()),
                }
            }
        }

        impl TryFrom<ExecutionPayloadHeader> for $wrapper_type_full {
            type Error = BeaconStateError;
            fn try_from(_: ExecutionPayloadHeader) -> Result<Self, Self::Error> {
                Err(BeaconStateError::PayloadConversionLogicFlaw)
            }
        }

        impl TryFrom<$wrapped_type_header> for $wrapper_type_full {
            type Error = BeaconStateError;
            fn try_from(_: $wrapped_type_header) -> Result<Self, Self::Error> {
                Err(BeaconStateError::PayloadConversionLogicFlaw)
            }
        }

        impl TryInto<$wrapper_type_full> for FullPayload {
            type Error = BeaconStateError;

            fn try_into(self) -> Result<$wrapper_type_full, Self::Error> {
                match self {
                    FullPayload::$fork_variant(payload) => Ok(payload),
                    _ => Err(BeaconStateError::PayloadConversionLogicFlaw),
                }
            }
        }
    };
}

impl_exec_payload_for_fork!(
    BlindedPayloadBellatrix,
    FullPayloadBellatrix,
    ExecutionPayloadHeaderBellatrix,
    ExecutionPayloadBellatrix,
    Bellatrix
);
impl_exec_payload_for_fork!(
    BlindedPayloadCapella,
    FullPayloadCapella,
    ExecutionPayloadHeaderCapella,
    ExecutionPayloadCapella,
    Capella
);
impl_exec_payload_for_fork!(
    BlindedPayloadDeneb,
    FullPayloadDeneb,
    ExecutionPayloadHeaderDeneb,
    ExecutionPayloadDeneb,
    Deneb
);
impl_exec_payload_for_fork!(
    BlindedPayloadElectra,
    FullPayloadElectra,
    ExecutionPayloadHeaderElectra,
    ExecutionPayloadElectra,
    Electra
);
impl_exec_payload_for_fork!(
    BlindedPayloadFulu,
    FullPayloadFulu,
    ExecutionPayloadHeaderFulu,
    ExecutionPayloadFulu,
    Fulu
);

impl AbstractExecPayload for BlindedPayload {
    type Ref<'a> = BlindedPayloadRef<'a>;
    type Bellatrix = BlindedPayloadBellatrix;
    type Capella = BlindedPayloadCapella;
    type Deneb = BlindedPayloadDeneb;
    type Electra = BlindedPayloadElectra;
    type Fulu = BlindedPayloadFulu;
}

impl From<ExecutionPayload> for BlindedPayload {
    fn from(payload: ExecutionPayload) -> Self {
        // This implementation is a bit wasteful in that it discards the payload body.
        // Required by the top-level constraint on AbstractExecPayload but could maybe be loosened
        // in future.
        map_execution_payload_into_blinded_payload!(payload, |inner, cons| cons(From::from(
            Cow::Owned(inner)
        )))
    }
}

impl From<ExecutionPayloadHeader> for BlindedPayload {
    fn from(execution_payload_header: ExecutionPayloadHeader) -> Self {
        match execution_payload_header {
            ExecutionPayloadHeader::Bellatrix(execution_payload_header) => {
                Self::Bellatrix(BlindedPayloadBellatrix {
                    execution_payload_header,
                })
            }
            ExecutionPayloadHeader::Capella(execution_payload_header) => {
                Self::Capella(BlindedPayloadCapella {
                    execution_payload_header,
                })
            }
            ExecutionPayloadHeader::Deneb(execution_payload_header) => {
                Self::Deneb(BlindedPayloadDeneb {
                    execution_payload_header,
                })
            }
            ExecutionPayloadHeader::Electra(execution_payload_header) => {
                Self::Electra(BlindedPayloadElectra {
                    execution_payload_header,
                })
            }
            ExecutionPayloadHeader::Fulu(execution_payload_header) => {
                Self::Fulu(BlindedPayloadFulu {
                    execution_payload_header,
                })
            }
        }
    }
}

impl From<BlindedPayload> for ExecutionPayloadHeader {
    fn from(blinded: BlindedPayload) -> Self {
        match blinded {
            BlindedPayload::Bellatrix(blinded_payload) => {
                ExecutionPayloadHeader::Bellatrix(blinded_payload.execution_payload_header)
            }
            BlindedPayload::Capella(blinded_payload) => {
                ExecutionPayloadHeader::Capella(blinded_payload.execution_payload_header)
            }
            BlindedPayload::Deneb(blinded_payload) => {
                ExecutionPayloadHeader::Deneb(blinded_payload.execution_payload_header)
            }
            BlindedPayload::Electra(blinded_payload) => {
                ExecutionPayloadHeader::Electra(blinded_payload.execution_payload_header)
            }
            BlindedPayload::Fulu(blinded_payload) => {
                ExecutionPayloadHeader::Fulu(blinded_payload.execution_payload_header)
            }
        }
    }
}

/// The block production flow version to be used.
pub enum BlockProductionVersion {
    V3,
    BlindedV2,
    FullV2,
}
