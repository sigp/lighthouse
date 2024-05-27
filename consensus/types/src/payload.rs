use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::borrow::Cow;
use std::fmt::Debug;
use std::hash::Hash;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(Debug, PartialEq)]
pub enum BlockType {
    Blinded,
    Full,
}

/// A trait representing behavior of an `ExecutionPayload` that either has a full list of transactions
/// or a transaction hash in it's place.
pub trait ExecPayload<E: EthSpec>: Debug + Clone + PartialEq + Hash + TreeHash + Send {
    fn block_type() -> BlockType;

    /// Convert the payload into a payload header.
    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<E>;

    /// We provide a subset of field accessors, for the fields used in `consensus`.
    ///
    /// More fields can be added here if you wish.
    fn parent_hash(&self) -> ExecutionBlockHash;
    fn prev_randao(&self) -> Hash256;
    fn block_number(&self) -> u64;
    fn timestamp(&self) -> u64;
    fn block_hash(&self) -> ExecutionBlockHash;
    fn fee_recipient(&self) -> Address;
    fn gas_limit(&self) -> u64;
    fn transactions(&self) -> Option<&Transactions<E>>;
    /// fork-specific fields
    fn withdrawals_root(&self) -> Result<Hash256, Error>;
    fn blob_gas_used(&self) -> Result<u64, Error>;

    /// Is this a default payload with 0x0 roots for transactions and withdrawals?
    fn is_default_with_zero_roots(&self) -> bool;

    /// Is this a default payload with the hash of the empty list for transactions and withdrawals?
    fn is_default_with_empty_roots(&self) -> bool;
}

/// `ExecPayload` functionality the requires ownership.
pub trait OwnedExecPayload<E: EthSpec>:
    ExecPayload<E>
    + Default
    + Serialize
    + DeserializeOwned
    + Encode
    + Decode
    + TestRandom
    + for<'a> arbitrary::Arbitrary<'a>
    + 'static
{
}

impl<E: EthSpec, P> OwnedExecPayload<E> for P where
    P: ExecPayload<E>
        + Default
        + Serialize
        + DeserializeOwned
        + Encode
        + Decode
        + TestRandom
        + for<'a> arbitrary::Arbitrary<'a>
        + 'static
{
}

pub trait AbstractExecPayload<E: EthSpec>:
    ExecPayload<E>
    + Sized
    + From<ExecutionPayload<E>>
    + TryFrom<ExecutionPayloadHeader<E>>
    + TryInto<Self::Bellatrix>
    + TryInto<Self::Capella>
    + TryInto<Self::Deneb>
    + TryInto<Self::Electra>
{
    type Ref<'a>: ExecPayload<E>
        + Copy
        + From<&'a Self::Bellatrix>
        + From<&'a Self::Capella>
        + From<&'a Self::Deneb>
        + From<&'a Self::Electra>;

    type Bellatrix: OwnedExecPayload<E>
        + Into<Self>
        + for<'a> From<Cow<'a, ExecutionPayloadBellatrix<E>>>
        + TryFrom<ExecutionPayloadHeaderBellatrix<E>>;
    type Capella: OwnedExecPayload<E>
        + Into<Self>
        + for<'a> From<Cow<'a, ExecutionPayloadCapella<E>>>
        + TryFrom<ExecutionPayloadHeaderCapella<E>>;
    type Deneb: OwnedExecPayload<E>
        + Into<Self>
        + for<'a> From<Cow<'a, ExecutionPayloadDeneb<E>>>
        + TryFrom<ExecutionPayloadHeaderDeneb<E>>;
    type Electra: OwnedExecPayload<E>
        + Into<Self>
        + for<'a> From<Cow<'a, ExecutionPayloadElectra<E>>>
        + TryFrom<ExecutionPayloadHeaderElectra<E>>;
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TestRandom,
            TreeHash,
            Derivative,
            arbitrary::Arbitrary,
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
        ssz(struct_behaviour = "transparent"),
    ),
    ref_attributes(
        derive(Debug, Derivative, TreeHash),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        tree_hash(enum_behaviour = "transparent"),
    ),
    map_into(ExecutionPayload),
    map_ref_into(ExecutionPayloadRef),
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant")
)]
#[derive(Debug, Clone, Serialize, Deserialize, TreeHash, Derivative, arbitrary::Arbitrary)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct FullPayload<E: EthSpec> {
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "execution_payload_bellatrix")
    )]
    pub execution_payload: ExecutionPayloadBellatrix<E>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: ExecutionPayloadDeneb<E>,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    pub execution_payload: ExecutionPayloadElectra<E>,
}

impl<E: EthSpec> From<FullPayload<E>> for ExecutionPayload<E> {
    fn from(full_payload: FullPayload<E>) -> Self {
        map_full_payload_into_execution_payload!(full_payload, move |payload, cons| {
            cons(payload.execution_payload)
        })
    }
}

impl<'a, E: EthSpec> From<FullPayloadRef<'a, E>> for ExecutionPayload<E> {
    fn from(full_payload_ref: FullPayloadRef<'a, E>) -> Self {
        map_full_payload_ref!(&'a _, full_payload_ref, move |payload, cons| {
            cons(payload);
            payload.execution_payload.clone().into()
        })
    }
}

impl<'a, E: EthSpec> From<FullPayloadRef<'a, E>> for FullPayload<E> {
    fn from(full_payload_ref: FullPayloadRef<'a, E>) -> Self {
        map_full_payload_ref!(&'a _, full_payload_ref, move |payload, cons| {
            cons(payload);
            payload.clone().into()
        })
    }
}

impl<E: EthSpec> ExecPayload<E> for FullPayload<E> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header<'a>(&'a self) -> ExecutionPayloadHeader<E> {
        map_full_payload_ref!(&'a _, self.to_ref(), move |inner, cons| {
            cons(inner);
            let exec_payload_ref: ExecutionPayloadRef<'a, E> = From::from(&inner.execution_payload);
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

    fn transactions<'a>(&'a self) -> Option<&'a Transactions<E>> {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            Some(&payload.execution_payload.transactions)
        })
    }

    fn withdrawals_root(&self) -> Result<Hash256, Error> {
        match self {
            FullPayload::Bellatrix(_) => Err(Error::IncorrectStateVariant),
            FullPayload::Capella(ref inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
            FullPayload::Deneb(ref inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
            FullPayload::Electra(ref inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
        }
    }

    fn blob_gas_used(&self) -> Result<u64, Error> {
        match self {
            FullPayload::Bellatrix(_) | FullPayload::Capella(_) => {
                Err(Error::IncorrectStateVariant)
            }
            FullPayload::Deneb(ref inner) => Ok(inner.execution_payload.blob_gas_used),
            FullPayload::Electra(ref inner) => Ok(inner.execution_payload.blob_gas_used),
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

impl<E: EthSpec> FullPayload<E> {
    pub fn execution_payload(self) -> ExecutionPayload<E> {
        map_full_payload_into_execution_payload!(self, |inner, cons| {
            cons(inner.execution_payload)
        })
    }

    pub fn default_at_fork(fork_name: ForkName) -> Result<Self, Error> {
        match fork_name {
            ForkName::Base | ForkName::Altair => Err(Error::IncorrectStateVariant),
            ForkName::Bellatrix => Ok(FullPayloadBellatrix::default().into()),
            ForkName::Capella => Ok(FullPayloadCapella::default().into()),
            ForkName::Deneb => Ok(FullPayloadDeneb::default().into()),
            ForkName::Electra => Ok(FullPayloadElectra::default().into()),
        }
    }
}

impl<'a, E: EthSpec> FullPayloadRef<'a, E> {
    pub fn execution_payload_ref(self) -> ExecutionPayloadRef<'a, E> {
        map_full_payload_ref_into_execution_payload_ref!(&'a _, self, |inner, cons| {
            cons(&inner.execution_payload)
        })
    }
}

impl<'b, E: EthSpec> ExecPayload<E> for FullPayloadRef<'b, E> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header<'a>(&'a self) -> ExecutionPayloadHeader<E> {
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

    fn transactions<'a>(&'a self) -> Option<&'a Transactions<E>> {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            Some(&payload.execution_payload.transactions)
        })
    }

    fn withdrawals_root(&self) -> Result<Hash256, Error> {
        match self {
            FullPayloadRef::Bellatrix(_) => Err(Error::IncorrectStateVariant),
            FullPayloadRef::Capella(inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
            FullPayloadRef::Deneb(inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
            FullPayloadRef::Electra(inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
        }
    }

    fn blob_gas_used(&self) -> Result<u64, Error> {
        match self {
            FullPayloadRef::Bellatrix(_) | FullPayloadRef::Capella(_) => {
                Err(Error::IncorrectStateVariant)
            }
            FullPayloadRef::Deneb(inner) => Ok(inner.execution_payload.blob_gas_used),
            FullPayloadRef::Electra(inner) => Ok(inner.execution_payload.blob_gas_used),
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

impl<E: EthSpec> AbstractExecPayload<E> for FullPayload<E> {
    type Ref<'a> = FullPayloadRef<'a, E>;
    type Bellatrix = FullPayloadBellatrix<E>;
    type Capella = FullPayloadCapella<E>;
    type Deneb = FullPayloadDeneb<E>;
    type Electra = FullPayloadElectra<E>;
}

impl<E: EthSpec> From<ExecutionPayload<E>> for FullPayload<E> {
    fn from(execution_payload: ExecutionPayload<E>) -> Self {
        map_execution_payload_into_full_payload!(execution_payload, |inner, cons| {
            cons(inner.into())
        })
    }
}

impl<E: EthSpec> TryFrom<ExecutionPayloadHeader<E>> for FullPayload<E> {
    type Error = ();
    fn try_from(_: ExecutionPayloadHeader<E>) -> Result<Self, Self::Error> {
        Err(())
    }
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra),
    variant_attributes(
        derive(
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TestRandom,
            TreeHash,
            Derivative,
            arbitrary::Arbitrary
        ),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        arbitrary(bound = "E: EthSpec"),
        ssz(struct_behaviour = "transparent"),
    ),
    ref_attributes(
        derive(Debug, Derivative, TreeHash),
        derivative(PartialEq, Hash(bound = "E: EthSpec")),
        tree_hash(enum_behaviour = "transparent"),
    ),
    map_into(ExecutionPayloadHeader),
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant")
)]
#[derive(Debug, Clone, Serialize, Deserialize, TreeHash, Derivative, arbitrary::Arbitrary)]
#[derivative(PartialEq, Hash(bound = "E: EthSpec"))]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct BlindedPayload<E: EthSpec> {
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "execution_payload_bellatrix")
    )]
    pub execution_payload_header: ExecutionPayloadHeaderBellatrix<E>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload_header: ExecutionPayloadHeaderCapella<E>,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload_header: ExecutionPayloadHeaderDeneb<E>,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    pub execution_payload_header: ExecutionPayloadHeaderElectra<E>,
}

impl<'a, E: EthSpec> From<BlindedPayloadRef<'a, E>> for BlindedPayload<E> {
    fn from(blinded_payload_ref: BlindedPayloadRef<'a, E>) -> Self {
        map_blinded_payload_ref!(&'a _, blinded_payload_ref, move |payload, cons| {
            cons(payload);
            payload.clone().into()
        })
    }
}

impl<E: EthSpec> ExecPayload<E> for BlindedPayload<E> {
    fn block_type() -> BlockType {
        BlockType::Blinded
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<E> {
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

    fn transactions(&self) -> Option<&Transactions<E>> {
        None
    }

    fn withdrawals_root(&self) -> Result<Hash256, Error> {
        match self {
            BlindedPayload::Bellatrix(_) => Err(Error::IncorrectStateVariant),
            BlindedPayload::Capella(ref inner) => {
                Ok(inner.execution_payload_header.withdrawals_root)
            }
            BlindedPayload::Deneb(ref inner) => Ok(inner.execution_payload_header.withdrawals_root),
            BlindedPayload::Electra(ref inner) => {
                Ok(inner.execution_payload_header.withdrawals_root)
            }
        }
    }

    fn blob_gas_used(&self) -> Result<u64, Error> {
        match self {
            BlindedPayload::Bellatrix(_) | BlindedPayload::Capella(_) => {
                Err(Error::IncorrectStateVariant)
            }
            BlindedPayload::Deneb(ref inner) => Ok(inner.execution_payload_header.blob_gas_used),
            BlindedPayload::Electra(ref inner) => Ok(inner.execution_payload_header.blob_gas_used),
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

impl<'b, E: EthSpec> ExecPayload<E> for BlindedPayloadRef<'b, E> {
    fn block_type() -> BlockType {
        BlockType::Blinded
    }

    fn to_execution_payload_header<'a>(&'a self) -> ExecutionPayloadHeader<E> {
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

    fn transactions(&self) -> Option<&Transactions<E>> {
        None
    }

    fn withdrawals_root(&self) -> Result<Hash256, Error> {
        match self {
            BlindedPayloadRef::Bellatrix(_) => Err(Error::IncorrectStateVariant),
            BlindedPayloadRef::Capella(inner) => {
                Ok(inner.execution_payload_header.withdrawals_root)
            }
            BlindedPayloadRef::Deneb(inner) => Ok(inner.execution_payload_header.withdrawals_root),
            BlindedPayloadRef::Electra(inner) => {
                Ok(inner.execution_payload_header.withdrawals_root)
            }
        }
    }

    fn blob_gas_used(&self) -> Result<u64, Error> {
        match self {
            BlindedPayloadRef::Bellatrix(_) | BlindedPayloadRef::Capella(_) => {
                Err(Error::IncorrectStateVariant)
            }
            BlindedPayloadRef::Deneb(inner) => Ok(inner.execution_payload_header.blob_gas_used),
            BlindedPayloadRef::Electra(inner) => Ok(inner.execution_payload_header.blob_gas_used),
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
        impl<E: EthSpec> ExecPayload<E> for $wrapper_type<E> {
            fn block_type() -> BlockType {
                BlockType::$block_type_variant
            }

            fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<E> {
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

            fn transactions(&self) -> Option<&Transactions<E>> {
                let f = $f;
                f(self)
            }

            fn withdrawals_root(&self) -> Result<Hash256, Error> {
                let g = $g;
                g(self)
            }

            fn blob_gas_used(&self) -> Result<u64, Error> {
                let h = $h;
                h(self)
            }
        }

        impl<E: EthSpec> From<$wrapped_type<E>> for $wrapper_type<E> {
            fn from($wrapped_field: $wrapped_type<E>) -> Self {
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
                |wrapper: &$wrapper_type_header<E>| {
                    wrapper.execution_payload_header
                        == $wrapped_type_header::from(&$wrapped_type_full::default())
                }
            },
            { |_| { None } },
            {
                let c: for<'a> fn(&'a $wrapper_type_header<E>) -> Result<Hash256, Error> =
                    |payload: &$wrapper_type_header<E>| {
                        let wrapper_ref_type = BlindedPayloadRef::$fork_variant(&payload);
                        wrapper_ref_type.withdrawals_root()
                    };
                c
            },
            {
                let c: for<'a> fn(&'a $wrapper_type_header<E>) -> Result<u64, Error> =
                    |payload: &$wrapper_type_header<E>| {
                        let wrapper_ref_type = BlindedPayloadRef::$fork_variant(&payload);
                        wrapper_ref_type.blob_gas_used()
                    };
                c
            }
        );

        impl<E: EthSpec> TryInto<$wrapper_type_header<E>> for BlindedPayload<E> {
            type Error = Error;

            fn try_into(self) -> Result<$wrapper_type_header<E>, Self::Error> {
                match self {
                    BlindedPayload::$fork_variant(payload) => Ok(payload),
                    _ => Err(Error::IncorrectStateVariant),
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
        impl<E: EthSpec> Default for $wrapper_type_header<E> {
            fn default() -> Self {
                Self {
                    execution_payload_header: $wrapped_type_header::from(
                        &$wrapped_type_full::default(),
                    ),
                }
            }
        }

        impl<E: EthSpec> TryFrom<ExecutionPayloadHeader<E>> for $wrapper_type_header<E> {
            type Error = Error;
            fn try_from(header: ExecutionPayloadHeader<E>) -> Result<Self, Self::Error> {
                match header {
                    ExecutionPayloadHeader::$fork_variant(execution_payload_header) => {
                        Ok(execution_payload_header.into())
                    }
                    _ => Err(Error::PayloadConversionLogicFlaw),
                }
            }
        }

        // BlindedPayload* from CoW reference to ExecutionPayload* (hopefully just a reference).
        impl<'a, E: EthSpec> From<Cow<'a, $wrapped_type_full<E>>> for $wrapper_type_header<E> {
            fn from(execution_payload: Cow<'a, $wrapped_type_full<E>>) -> Self {
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
                |wrapper: &$wrapper_type_full<E>| {
                    wrapper.execution_payload == $wrapped_type_full::default()
                }
            },
            {
                let c: for<'a> fn(&'a $wrapper_type_full<E>) -> Option<&'a Transactions<E>> =
                    |payload: &$wrapper_type_full<E>| Some(&payload.execution_payload.transactions);
                c
            },
            {
                let c: for<'a> fn(&'a $wrapper_type_full<E>) -> Result<Hash256, Error> =
                    |payload: &$wrapper_type_full<E>| {
                        let wrapper_ref_type = FullPayloadRef::$fork_variant(&payload);
                        wrapper_ref_type.withdrawals_root()
                    };
                c
            },
            {
                let c: for<'a> fn(&'a $wrapper_type_full<E>) -> Result<u64, Error> =
                    |payload: &$wrapper_type_full<E>| {
                        let wrapper_ref_type = FullPayloadRef::$fork_variant(&payload);
                        wrapper_ref_type.blob_gas_used()
                    };
                c
            }
        );

        impl<E: EthSpec> Default for $wrapper_type_full<E> {
            fn default() -> Self {
                Self {
                    execution_payload: $wrapped_type_full::default(),
                }
            }
        }

        // FullPayload * from CoW reference to ExecutionPayload* (hopefully already owned).
        impl<'a, E: EthSpec> From<Cow<'a, $wrapped_type_full<E>>> for $wrapper_type_full<E> {
            fn from(execution_payload: Cow<'a, $wrapped_type_full<E>>) -> Self {
                Self {
                    execution_payload: $wrapped_type_full::from(execution_payload.into_owned()),
                }
            }
        }

        impl<E: EthSpec> TryFrom<ExecutionPayloadHeader<E>> for $wrapper_type_full<E> {
            type Error = Error;
            fn try_from(_: ExecutionPayloadHeader<E>) -> Result<Self, Self::Error> {
                Err(Error::PayloadConversionLogicFlaw)
            }
        }

        impl<E: EthSpec> TryFrom<$wrapped_type_header<E>> for $wrapper_type_full<E> {
            type Error = Error;
            fn try_from(_: $wrapped_type_header<E>) -> Result<Self, Self::Error> {
                Err(Error::PayloadConversionLogicFlaw)
            }
        }

        impl<E: EthSpec> TryInto<$wrapper_type_full<E>> for FullPayload<E> {
            type Error = Error;

            fn try_into(self) -> Result<$wrapper_type_full<E>, Self::Error> {
                match self {
                    FullPayload::$fork_variant(payload) => Ok(payload),
                    _ => Err(Error::PayloadConversionLogicFlaw),
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

impl<E: EthSpec> AbstractExecPayload<E> for BlindedPayload<E> {
    type Ref<'a> = BlindedPayloadRef<'a, E>;
    type Bellatrix = BlindedPayloadBellatrix<E>;
    type Capella = BlindedPayloadCapella<E>;
    type Deneb = BlindedPayloadDeneb<E>;
    type Electra = BlindedPayloadElectra<E>;
}

impl<E: EthSpec> From<ExecutionPayload<E>> for BlindedPayload<E> {
    fn from(payload: ExecutionPayload<E>) -> Self {
        // This implementation is a bit wasteful in that it discards the payload body.
        // Required by the top-level constraint on AbstractExecPayload but could maybe be loosened
        // in future.
        map_execution_payload_into_blinded_payload!(payload, |inner, cons| cons(From::from(
            Cow::Owned(inner)
        )))
    }
}

impl<E: EthSpec> From<ExecutionPayloadHeader<E>> for BlindedPayload<E> {
    fn from(execution_payload_header: ExecutionPayloadHeader<E>) -> Self {
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
        }
    }
}

impl<E: EthSpec> From<BlindedPayload<E>> for ExecutionPayloadHeader<E> {
    fn from(blinded: BlindedPayload<E>) -> Self {
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
        }
    }
}

/// The block production flow version to be used.
pub enum BlockProductionVersion {
    V3,
    BlindedV2,
    FullV2,
}
