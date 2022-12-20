use crate::{test_utils::TestRandom, *};
use derivative::Derivative;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::convert::TryFrom;
use std::fmt::Debug;
use std::hash::Hash;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

#[derive(Debug)]
pub enum BlockType {
    Blinded,
    Full,
}

/// A trait representing behavior of an `ExecutionPayload` that either has a full list of transactions
/// or a transaction hash in it's place.
pub trait ExecPayload<T: EthSpec>: Debug + Clone + PartialEq + Hash + TreeHash + Send {
    fn block_type() -> BlockType;

    /// Convert the payload into a payload header.
    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T>;

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
    fn transactions(&self) -> Option<&Transactions<T>>;
    /// fork-specific fields
    fn withdrawals_root(&self) -> Result<Hash256, Error>;

    /// Is this a default payload with 0x0 roots for transactions and withdrawals?
    fn is_default_with_zero_roots(&self) -> bool;

    /// Is this a default payload with the hash of the empty list for transactions and withdrawals?
    fn is_default_with_empty_roots(&self) -> bool;
}

/// `ExecPayload` functionality the requires ownership.
pub trait OwnedExecPayload<T: EthSpec>:
    ExecPayload<T> + Default + Serialize + DeserializeOwned + Encode + Decode + TestRandom + 'static
{
}

impl<T: EthSpec, P> OwnedExecPayload<T> for P where
    P: ExecPayload<T>
        + Default
        + Serialize
        + DeserializeOwned
        + Encode
        + Decode
        + TestRandom
        + 'static
{
}

pub trait AbstractExecPayload<T: EthSpec>:
    ExecPayload<T>
    + Sized
    + From<ExecutionPayload<T>>
    + TryFrom<ExecutionPayloadHeader<T>>
    + TryInto<Self::Merge>
    + TryInto<Self::Capella>
    + TryInto<Self::Eip4844>
{
    type Ref<'a>: ExecPayload<T>
        + Copy
        + From<&'a Self::Merge>
        + From<&'a Self::Capella>
        + From<&'a Self::Eip4844>;

    type Merge: OwnedExecPayload<T>
        + Into<Self>
        + From<ExecutionPayloadMerge<T>>
        + TryFrom<ExecutionPayloadHeaderMerge<T>>;
    type Capella: OwnedExecPayload<T>
        + Into<Self>
        + From<ExecutionPayloadCapella<T>>
        + TryFrom<ExecutionPayloadHeaderCapella<T>>;
    type Eip4844: OwnedExecPayload<T>
        + Into<Self>
        + From<ExecutionPayloadEip4844<T>>
        + TryFrom<ExecutionPayloadHeaderEip4844<T>>;

    fn default_at_fork(fork_name: ForkName) -> Self;
}

#[superstruct(
    variants(Merge, Capella, Eip4844),
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
        ),
        derivative(PartialEq, Hash(bound = "T: EthSpec")),
        serde(bound = "T: EthSpec", deny_unknown_fields),
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary)),
        ssz(struct_behaviour = "transparent"),
    ),
    ref_attributes(
        derive(Debug, Derivative, TreeHash),
        derivative(PartialEq, Hash(bound = "T: EthSpec")),
        tree_hash(enum_behaviour = "transparent"),
    ),
    map_into(ExecutionPayload),
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant")
)]
#[derive(Debug, Clone, Serialize, Deserialize, TreeHash, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct FullPayload<T: EthSpec> {
    #[superstruct(only(Merge), partial_getter(rename = "execution_payload_merge"))]
    pub execution_payload: ExecutionPayloadMerge<T>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella<T>,
    #[superstruct(only(Eip4844), partial_getter(rename = "execution_payload_eip4844"))]
    pub execution_payload: ExecutionPayloadEip4844<T>,
}

impl<T: EthSpec> From<FullPayload<T>> for ExecutionPayload<T> {
    fn from(full_payload: FullPayload<T>) -> Self {
        match full_payload {
            FullPayload::Merge(payload) => ExecutionPayload::Merge(payload.execution_payload),
            FullPayload::Capella(payload) => ExecutionPayload::Capella(payload.execution_payload),
            FullPayload::Eip4844(payload) => ExecutionPayload::Eip4844(payload.execution_payload),
        }
    }
}

impl<'a, T: EthSpec> From<FullPayloadRef<'a, T>> for ExecutionPayload<T> {
    fn from(full_payload_ref: FullPayloadRef<'a, T>) -> Self {
        match full_payload_ref {
            FullPayloadRef::Merge(payload) => {
                ExecutionPayload::Merge(payload.execution_payload.clone())
            }
            FullPayloadRef::Capella(payload) => {
                ExecutionPayload::Capella(payload.execution_payload.clone())
            }
            FullPayloadRef::Eip4844(payload) => {
                ExecutionPayload::Eip4844(payload.execution_payload.clone())
            }
        }
    }
}

// FIXME: can this be implemented as Deref or Clone somehow?
impl<'a, T: EthSpec> From<FullPayloadRef<'a, T>> for FullPayload<T> {
    fn from(full_payload_ref: FullPayloadRef<'a, T>) -> Self {
        map_full_payload_ref!(&'a _, full_payload_ref, move |payload, cons| {
            cons(payload);
            payload.clone().into()
        })
    }
}

impl<T: EthSpec> ExecPayload<T> for FullPayload<T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        let payload = map_full_payload_into_execution_payload!(self.clone(), |inner, cons| {
            cons(inner.execution_payload)
        });
        ExecutionPayloadHeader::from(payload)
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

    fn transactions<'a>(&'a self) -> Option<&'a Transactions<T>> {
        map_full_payload_ref!(&'a _, self.to_ref(), move |payload, cons| {
            cons(payload);
            Some(&payload.execution_payload.transactions)
        })
    }

    fn withdrawals_root(&self) -> Result<Hash256, Error> {
        match self {
            FullPayload::Merge(_) => Err(Error::IncorrectStateVariant),
            FullPayload::Capella(ref inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
            FullPayload::Eip4844(ref inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
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

impl<T: EthSpec> FullPayload<T> {
    pub fn execution_payload(&self) -> ExecutionPayload<T> {
        map_full_payload_into_execution_payload!(self.clone(), |inner, cons| {
            cons(inner.execution_payload)
        })
    }
}

impl<'b, T: EthSpec> ExecPayload<T> for FullPayloadRef<'b, T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header<'a>(&'a self) -> ExecutionPayloadHeader<T> {
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

    fn transactions<'a>(&'a self) -> Option<&'a Transactions<T>> {
        map_full_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            Some(&payload.execution_payload.transactions)
        })
    }

    fn withdrawals_root(&self) -> Result<Hash256, Error> {
        match self {
            FullPayloadRef::Merge(_) => Err(Error::IncorrectStateVariant),
            FullPayloadRef::Capella(inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
            FullPayloadRef::Eip4844(inner) => {
                Ok(inner.execution_payload.withdrawals.tree_hash_root())
            }
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

impl<T: EthSpec> AbstractExecPayload<T> for FullPayload<T> {
    type Ref<'a> = FullPayloadRef<'a, T>;
    type Merge = FullPayloadMerge<T>;
    type Capella = FullPayloadCapella<T>;
    type Eip4844 = FullPayloadEip4844<T>;

    fn default_at_fork(fork_name: ForkName) -> Self {
        match fork_name {
            //FIXME(sean) error handling
            ForkName::Base | ForkName::Altair => panic!(),
            ForkName::Merge => FullPayloadMerge::default().into(),
            ForkName::Capella => FullPayloadCapella::default().into(),
            ForkName::Eip4844 => FullPayloadEip4844::default().into(),
        }
    }
}

impl<T: EthSpec> From<ExecutionPayload<T>> for FullPayload<T> {
    fn from(execution_payload: ExecutionPayload<T>) -> Self {
        match execution_payload {
            ExecutionPayload::Merge(execution_payload) => {
                Self::Merge(FullPayloadMerge { execution_payload })
            }
            ExecutionPayload::Capella(execution_payload) => {
                Self::Capella(FullPayloadCapella { execution_payload })
            }
            ExecutionPayload::Eip4844(execution_payload) => {
                Self::Eip4844(FullPayloadEip4844 { execution_payload })
            }
        }
    }
}

impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for FullPayload<T> {
    type Error = ();
    fn try_from(_: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
        Err(())
    }
}

#[superstruct(
    variants(Merge, Capella, Eip4844),
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
        ),
        derivative(PartialEq, Hash(bound = "T: EthSpec")),
        serde(bound = "T: EthSpec", deny_unknown_fields),
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary)),
        ssz(struct_behaviour = "transparent"),
    ),
    ref_attributes(
        derive(Debug, Derivative, TreeHash),
        derivative(PartialEq, Hash(bound = "T: EthSpec")),
        tree_hash(enum_behaviour = "transparent"),
    ),
    map_into(ExecutionPayloadHeader),
    cast_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "BeaconStateError::IncorrectStateVariant")
)]
#[derive(Debug, Clone, Serialize, Deserialize, TreeHash, Derivative)]
#[derivative(PartialEq, Hash(bound = "T: EthSpec"))]
#[serde(bound = "T: EthSpec")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct BlindedPayload<T: EthSpec> {
    #[superstruct(only(Merge), partial_getter(rename = "execution_payload_merge"))]
    pub execution_payload_header: ExecutionPayloadHeaderMerge<T>,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload_header: ExecutionPayloadHeaderCapella<T>,
    #[superstruct(only(Eip4844), partial_getter(rename = "execution_payload_eip4844"))]
    pub execution_payload_header: ExecutionPayloadHeaderEip4844<T>,
}

impl<'a, T: EthSpec> From<BlindedPayloadRef<'a, T>> for BlindedPayload<T> {
    fn from(blinded_payload_ref: BlindedPayloadRef<'a, T>) -> Self {
        map_blinded_payload_ref!(&'a _, blinded_payload_ref, move |payload, cons| {
            cons(payload);
            payload.clone().into()
        })
    }
}

impl<T: EthSpec> ExecPayload<T> for BlindedPayload<T> {
    fn block_type() -> BlockType {
        BlockType::Blinded
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
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

    fn transactions(&self) -> Option<&Transactions<T>> {
        None
    }

    fn withdrawals_root(&self) -> Result<Hash256, Error> {
        match self {
            BlindedPayload::Merge(_) => Err(Error::IncorrectStateVariant),
            BlindedPayload::Capella(ref inner) => {
                Ok(inner.execution_payload_header.withdrawals_root)
            }
            BlindedPayload::Eip4844(ref inner) => {
                Ok(inner.execution_payload_header.withdrawals_root)
            }
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

impl<'b, T: EthSpec> ExecPayload<T> for BlindedPayloadRef<'b, T> {
    fn block_type() -> BlockType {
        BlockType::Blinded
    }

    fn to_execution_payload_header<'a>(&'a self) -> ExecutionPayloadHeader<T> {
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

    fn transactions(&self) -> Option<&Transactions<T>> {
        None
    }

    fn withdrawals_root(&self) -> Result<Hash256, Error> {
        match self {
            BlindedPayloadRef::Merge(_) => Err(Error::IncorrectStateVariant),
            BlindedPayloadRef::Capella(inner) => {
                Ok(inner.execution_payload_header.withdrawals_root)
            }
            BlindedPayloadRef::Eip4844(inner) => {
                Ok(inner.execution_payload_header.withdrawals_root)
            }
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
    ($wrapper_type:ident,           // BlindedPayloadMerge          |   FullPayloadMerge
     $wrapped_type:ident,           // ExecutionPayloadHeaderMerge  |   ExecutionPayloadMerge
     $wrapped_type_full:ident,      // ExecutionPayloadMerge        |   ExecutionPayloadMerge
     $wrapped_type_header:ident,    // ExecutionPayloadHeaderMerge  |   ExecutionPayloadHeaderMerge
     $wrapped_field:ident,          // execution_payload_header     |   execution_payload
     $fork_variant:ident,           // Merge                        |   Merge
     $block_type_variant:ident,     // Blinded                      |   Full
     $f:block,
     $g:block) => {
        impl<T: EthSpec> ExecPayload<T> for $wrapper_type<T> {
            fn block_type() -> BlockType {
                BlockType::$block_type_variant
            }

            fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
                ExecutionPayloadHeader::$fork_variant($wrapped_type_header::from(
                    self.$wrapped_field.clone(),
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
                // FIXME: is there a better way than ignoring this lint?
                // This is necessary because the first invocation of this macro might expand to:
                //     self.execution_payload_header == ExecutionPayloadHeaderMerge::from(ExecutionPayloadMerge::default())
                // but the second invocation might expand to:
                //     self.execution_payload == ExecutionPayloadMerge::from(ExecutionPayloadMerge::default())
                #[allow(clippy::cmp_owned)]
                {
                    self.$wrapped_field == $wrapped_type::from($wrapped_type_full::default())
                }
            }

            fn transactions(&self) -> Option<&Transactions<T>> {
                let f = $f;
                f(self)
            }

            fn withdrawals_root(&self) -> Result<Hash256, Error> {
                let g = $g;
                g(self)
            }
        }

        impl<T: EthSpec> From<$wrapped_type<T>> for $wrapper_type<T> {
            fn from($wrapped_field: $wrapped_type<T>) -> Self {
                Self { $wrapped_field }
            }
        }
    };
}

macro_rules! impl_exec_payload_for_fork {
    // BlindedPayloadMerge, FullPayloadMerge, ExecutionPayloadHeaderMerge, ExecutionPayloadMerge, Merge
    ($wrapper_type_header:ident, $wrapper_type_full:ident, $wrapped_type_header:ident, $wrapped_type_full:ident, $fork_variant:ident) => {
        //*************** Blinded payload implementations ******************//

        impl_exec_payload_common!(
            $wrapper_type_header, // BlindedPayloadMerge
            $wrapped_type_header, // ExecutionPayloadHeaderMerge
            $wrapped_type_full,   // ExecutionPayloadMerge
            $wrapped_type_header, // ExecutionPayloadHeaderMerge
            execution_payload_header,
            $fork_variant, // Merge
            Blinded,
            { |_| { None } },
            {
                let c: for<'a> fn(&'a $wrapper_type_header<T>) -> Result<Hash256, Error> =
                    |payload: &$wrapper_type_header<T>| {
                        let wrapper_ref_type = BlindedPayloadRef::$fork_variant(&payload);
                        wrapper_ref_type.withdrawals_root()
                    };
                c
            }
        );

        impl<T: EthSpec> TryInto<$wrapper_type_header<T>> for BlindedPayload<T> {
            type Error = Error;

            fn try_into(self) -> Result<$wrapper_type_header<T>, Self::Error> {
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
        impl<T: EthSpec> Default for $wrapper_type_header<T> {
            fn default() -> Self {
                Self {
                    execution_payload_header: $wrapped_type_header::from(
                        $wrapped_type_full::default(),
                    ),
                }
            }
        }

        impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for $wrapper_type_header<T> {
            type Error = Error;
            fn try_from(header: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
                match header {
                    ExecutionPayloadHeader::$fork_variant(execution_payload_header) => {
                        Ok(execution_payload_header.into())
                    }
                    _ => Err(Error::PayloadConversionLogicFlaw),
                }
            }
        }

        // FIXME(sproul): consider adding references to these From impls
        impl<T: EthSpec> From<$wrapped_type_full<T>> for $wrapper_type_header<T> {
            fn from(execution_payload: $wrapped_type_full<T>) -> Self {
                Self {
                    execution_payload_header: $wrapped_type_header::from(execution_payload),
                }
            }
        }

        //*************** Full payload implementations ******************//

        impl_exec_payload_common!(
            $wrapper_type_full,   // FullPayloadMerge
            $wrapped_type_full,   // ExecutionPayloadMerge
            $wrapped_type_full,   // ExecutionPayloadMerge
            $wrapped_type_header, // ExecutionPayloadHeaderMerge
            execution_payload,
            $fork_variant, // Merge
            Full,
            {
                let c: for<'a> fn(&'a $wrapper_type_full<T>) -> Option<&'a Transactions<T>> =
                    |payload: &$wrapper_type_full<T>| Some(&payload.execution_payload.transactions);
                c
            },
            {
                let c: for<'a> fn(&'a $wrapper_type_full<T>) -> Result<Hash256, Error> =
                    |payload: &$wrapper_type_full<T>| {
                        let wrapper_ref_type = FullPayloadRef::$fork_variant(&payload);
                        wrapper_ref_type.withdrawals_root()
                    };
                c
            }
        );

        impl<T: EthSpec> Default for $wrapper_type_full<T> {
            fn default() -> Self {
                Self {
                    execution_payload: $wrapped_type_full::default(),
                }
            }
        }

        impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for $wrapper_type_full<T> {
            type Error = Error;
            fn try_from(_: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
                Err(Error::PayloadConversionLogicFlaw)
            }
        }

        impl<T: EthSpec> TryFrom<$wrapped_type_header<T>> for $wrapper_type_full<T> {
            type Error = Error;
            fn try_from(_: $wrapped_type_header<T>) -> Result<Self, Self::Error> {
                Err(Error::PayloadConversionLogicFlaw)
            }
        }

        impl<T: EthSpec> TryInto<$wrapper_type_full<T>> for FullPayload<T> {
            type Error = Error;

            fn try_into(self) -> Result<$wrapper_type_full<T>, Self::Error> {
                match self {
                    FullPayload::$fork_variant(payload) => Ok(payload),
                    _ => Err(Error::PayloadConversionLogicFlaw),
                }
            }
        }
    };
}

impl_exec_payload_for_fork!(
    BlindedPayloadMerge,
    FullPayloadMerge,
    ExecutionPayloadHeaderMerge,
    ExecutionPayloadMerge,
    Merge
);
impl_exec_payload_for_fork!(
    BlindedPayloadCapella,
    FullPayloadCapella,
    ExecutionPayloadHeaderCapella,
    ExecutionPayloadCapella,
    Capella
);
impl_exec_payload_for_fork!(
    BlindedPayloadEip4844,
    FullPayloadEip4844,
    ExecutionPayloadHeaderEip4844,
    ExecutionPayloadEip4844,
    Eip4844
);

impl<T: EthSpec> AbstractExecPayload<T> for BlindedPayload<T> {
    type Ref<'a> = BlindedPayloadRef<'a, T>;
    type Merge = BlindedPayloadMerge<T>;
    type Capella = BlindedPayloadCapella<T>;
    type Eip4844 = BlindedPayloadEip4844<T>;

    fn default_at_fork(fork_name: ForkName) -> Self {
        match fork_name {
            //FIXME(sean) error handling
            ForkName::Base | ForkName::Altair => panic!(),
            ForkName::Merge => BlindedPayloadMerge::default().into(),
            ForkName::Capella => BlindedPayloadCapella::default().into(),
            ForkName::Eip4844 => BlindedPayloadEip4844::default().into(),
        }
    }
}

impl<T: EthSpec> From<ExecutionPayload<T>> for BlindedPayload<T> {
    fn from(payload: ExecutionPayload<T>) -> Self {
        match payload {
            ExecutionPayload::Merge(payload) => BlindedPayload::Merge(payload.into()),
            ExecutionPayload::Capella(payload) => BlindedPayload::Capella(payload.into()),
            ExecutionPayload::Eip4844(payload) => BlindedPayload::Eip4844(payload.into()),
        }
    }
}

impl<T: EthSpec> From<ExecutionPayloadHeader<T>> for BlindedPayload<T> {
    fn from(execution_payload_header: ExecutionPayloadHeader<T>) -> Self {
        match execution_payload_header {
            ExecutionPayloadHeader::Merge(execution_payload_header) => {
                Self::Merge(BlindedPayloadMerge {
                    execution_payload_header,
                })
            }
            ExecutionPayloadHeader::Capella(execution_payload_header) => {
                Self::Capella(BlindedPayloadCapella {
                    execution_payload_header,
                })
            }
            ExecutionPayloadHeader::Eip4844(execution_payload_header) => {
                Self::Eip4844(BlindedPayloadEip4844 {
                    execution_payload_header,
                })
            }
        }
    }
}

impl<T: EthSpec> From<BlindedPayload<T>> for ExecutionPayloadHeader<T> {
    fn from(blinded: BlindedPayload<T>) -> Self {
        match blinded {
            BlindedPayload::Merge(blinded_payload) => {
                ExecutionPayloadHeader::Merge(blinded_payload.execution_payload_header)
            }
            BlindedPayload::Capella(blinded_payload) => {
                ExecutionPayloadHeader::Capella(blinded_payload.execution_payload_header)
            }
            BlindedPayload::Eip4844(blinded_payload) => {
                ExecutionPayloadHeader::Eip4844(blinded_payload.execution_payload_header)
            }
        }
    }
}
