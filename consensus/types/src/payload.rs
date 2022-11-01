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

//  + TryFrom<ExecutionPayloadHeader<T>>
pub trait ExecPayload<T: EthSpec>: Debug + Clone + PartialEq + Hash + TreeHash + Send {
    fn block_type() -> BlockType;

    /// Convert the payload into a payload header.
    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T>;

    // We provide a subset of field accessors, for the fields used in `consensus`.
    //
    // More fields can be added here if you wish.
    fn parent_hash(&self) -> ExecutionBlockHash;
    fn prev_randao(&self) -> Hash256;
    fn block_number(&self) -> u64;
    fn timestamp(&self) -> u64;
    fn block_hash(&self) -> ExecutionBlockHash;
    fn fee_recipient(&self) -> Address;
    fn gas_limit(&self) -> u64;

    /// This will return `None` on blinded blocks or pre-merge blocks.
    fn transactions(&self) -> Option<&Transactions<T>>;

    // Is this a default payload? (pre-merge)
    fn is_default(&self) -> bool;
}

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
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))
    ),
    ref_attributes(
        derive(Debug, Derivative, TreeHash),
        derivative(PartialEq, Hash(bound = "T: EthSpec")),
        tree_hash(enum_behaviour = "transparent"),
    ),
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
    fn from(full_payload: FullPayloadRef<'a, T>) -> Self {
        match full_payload {
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

impl<T: EthSpec> ExecPayload<T> for FullPayloadMerge<T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        ExecutionPayloadHeader::Merge(ExecutionPayloadHeaderMerge::from(
            self.execution_payload.clone(),
        ))
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.execution_payload.parent_hash
    }

    fn prev_randao(&self) -> Hash256 {
        self.execution_payload.prev_randao
    }

    fn block_number(&self) -> u64 {
        self.execution_payload.block_number
    }

    fn timestamp(&self) -> u64 {
        self.execution_payload.timestamp
    }

    fn block_hash(&self) -> ExecutionBlockHash {
        self.execution_payload.block_hash
    }

    fn fee_recipient(&self) -> Address {
        self.execution_payload.fee_recipient
    }

    fn gas_limit(&self) -> u64 {
        self.execution_payload.gas_limit
    }

    fn transactions(&self) -> Option<&Transactions<T>> {
        Some(&self.execution_payload.transactions)
    }

    // TODO: can this function be optimized?
    fn is_default(&self) -> bool {
        self.execution_payload == ExecutionPayloadMerge::default()
    }
}
impl<T: EthSpec> ExecPayload<T> for FullPayloadCapella<T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        ExecutionPayloadHeader::Capella(ExecutionPayloadHeaderCapella::from(
            self.execution_payload.clone(),
        ))
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.execution_payload.parent_hash
    }

    fn prev_randao(&self) -> Hash256 {
        self.execution_payload.prev_randao
    }

    fn block_number(&self) -> u64 {
        self.execution_payload.block_number
    }

    fn timestamp(&self) -> u64 {
        self.execution_payload.timestamp
    }

    fn block_hash(&self) -> ExecutionBlockHash {
        self.execution_payload.block_hash
    }

    fn fee_recipient(&self) -> Address {
        self.execution_payload.fee_recipient
    }

    fn gas_limit(&self) -> u64 {
        self.execution_payload.gas_limit
    }

    fn transactions(&self) -> Option<&Transactions<T>> {
        Some(&self.execution_payload.transactions)
    }

    // TODO: can this function be optimized?
    fn is_default(&self) -> bool {
        self.execution_payload == ExecutionPayloadCapella::default()
    }
}
impl<T: EthSpec> ExecPayload<T> for FullPayloadEip4844<T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        ExecutionPayloadHeader::Eip4844(ExecutionPayloadHeaderEip4844::from(
            self.execution_payload.clone(),
        ))
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.execution_payload.parent_hash
    }

    fn prev_randao(&self) -> Hash256 {
        self.execution_payload.prev_randao
    }

    fn block_number(&self) -> u64 {
        self.execution_payload.block_number
    }

    fn timestamp(&self) -> u64 {
        self.execution_payload.timestamp
    }

    fn block_hash(&self) -> ExecutionBlockHash {
        self.execution_payload.block_hash
    }

    fn fee_recipient(&self) -> Address {
        self.execution_payload.fee_recipient
    }

    fn gas_limit(&self) -> u64 {
        self.execution_payload.gas_limit
    }

    fn transactions(&self) -> Option<&Transactions<T>> {
        Some(&self.execution_payload.transactions)
    }

    // TODO: can this function be optimized?
    fn is_default(&self) -> bool {
        self.execution_payload == ExecutionPayloadEip4844::default()
    }
}

impl<T: EthSpec> ExecPayload<T> for FullPayload<T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        match self {
            Self::Merge(payload) => payload.to_execution_payload_header(),
            Self::Capella(payload) => payload.to_execution_payload_header(),
            Self::Eip4844(payload) => payload.to_execution_payload_header(),
        }
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

    fn is_default(&self) -> bool {
        match self {
            Self::Merge(payload) => payload.is_default(),
            Self::Capella(payload) => payload.is_default(),
            Self::Eip4844(payload) => payload.is_default(),
        }
    }
}

impl<T: EthSpec> FullPayload<T> {
    pub fn execution_payload(&self) -> ExecutionPayload<T> {
        match self {
            Self::Merge(full) => ExecutionPayload::Merge(full.execution_payload.clone()),
            Self::Capella(full) => ExecutionPayload::Capella(full.execution_payload.clone()),
            Self::Eip4844(full) => ExecutionPayload::Eip4844(full.execution_payload.clone()),
        }
    }
}

impl<'b, T: EthSpec> ExecPayload<T> for FullPayloadRef<'b, T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        match self {
            Self::Merge(payload) => payload.to_execution_payload_header(),
            Self::Capella(payload) => payload.to_execution_payload_header(),
            Self::Eip4844(payload) => payload.to_execution_payload_header(),
        }
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

    // TODO: can this function be optimized?
    fn is_default<'a>(&'a self) -> bool {
        match self {
            Self::Merge(payload_ref) => {
                payload_ref.execution_payload == ExecutionPayloadMerge::default()
            }
            Self::Capella(payload_ref) => {
                payload_ref.execution_payload == ExecutionPayloadCapella::default()
            }
            Self::Eip4844(payload_ref) => {
                payload_ref.execution_payload == ExecutionPayloadEip4844::default()
            }
        }
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

//FIXME(sean) fix errors
impl<T: EthSpec> TryInto<FullPayloadMerge<T>> for FullPayload<T> {
    type Error = ();

    fn try_into(self) -> Result<FullPayloadMerge<T>, Self::Error> {
        match self {
            FullPayload::Merge(payload) => Ok(payload),
            FullPayload::Capella(_) => Err(()),
            FullPayload::Eip4844(_) => Err(()),
        }
    }
}
impl<T: EthSpec> TryInto<FullPayloadCapella<T>> for FullPayload<T> {
    type Error = ();

    fn try_into(self) -> Result<FullPayloadCapella<T>, Self::Error> {
        match self {
            FullPayload::Merge(_) => Err(()),
            FullPayload::Capella(payload) => Ok(payload),
            FullPayload::Eip4844(_) => Err(()),
        }
    }
}
impl<T: EthSpec> TryInto<FullPayloadEip4844<T>> for FullPayload<T> {
    type Error = ();

    fn try_into(self) -> Result<FullPayloadEip4844<T>, Self::Error> {
        match self {
            FullPayload::Merge(_) => Err(()),
            FullPayload::Capella(_) => Err(()),
            FullPayload::Eip4844(payload) => Ok(payload),
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

impl<T: EthSpec> From<ExecutionPayloadMerge<T>> for FullPayloadMerge<T> {
    fn from(execution_payload: ExecutionPayloadMerge<T>) -> Self {
        Self { execution_payload }
    }
}
impl<T: EthSpec> From<ExecutionPayloadCapella<T>> for FullPayloadCapella<T> {
    fn from(execution_payload: ExecutionPayloadCapella<T>) -> Self {
        Self { execution_payload }
    }
}
impl<T: EthSpec> From<ExecutionPayloadEip4844<T>> for FullPayloadEip4844<T> {
    fn from(execution_payload: ExecutionPayloadEip4844<T>) -> Self {
        Self { execution_payload }
    }
}

impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for FullPayloadMerge<T> {
    type Error = ();
    fn try_from(_: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
        Err(())
    }
}
impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for FullPayloadCapella<T> {
    type Error = ();
    fn try_from(_: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
        Err(())
    }
}
impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for FullPayloadEip4844<T> {
    type Error = ();
    fn try_from(_: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
        Err(())
    }
}

impl<T: EthSpec> TryFrom<ExecutionPayloadHeaderMerge<T>> for FullPayloadMerge<T> {
    type Error = ();
    fn try_from(_: ExecutionPayloadHeaderMerge<T>) -> Result<Self, Self::Error> {
        Err(())
    }
}
impl<T: EthSpec> TryFrom<ExecutionPayloadHeaderCapella<T>> for FullPayloadCapella<T> {
    type Error = ();
    fn try_from(_: ExecutionPayloadHeaderCapella<T>) -> Result<Self, Self::Error> {
        Err(())
    }
}
impl<T: EthSpec> TryFrom<ExecutionPayloadHeaderEip4844<T>> for FullPayloadEip4844<T> {
    type Error = ();
    fn try_from(_: ExecutionPayloadHeaderEip4844<T>) -> Result<Self, Self::Error> {
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
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))
    ),
    ref_attributes(
        derive(Debug, Derivative, TreeHash),
        derivative(PartialEq, Hash(bound = "T: EthSpec")),
        tree_hash(enum_behaviour = "transparent"),
    ),
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

impl<T: EthSpec> ExecPayload<T> for BlindedPayload<T> {
    fn block_type() -> BlockType {
        BlockType::Blinded
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        match self {
            Self::Merge(payload) => {
                ExecutionPayloadHeader::Merge(payload.execution_payload_header.clone())
            }
            Self::Capella(payload) => {
                ExecutionPayloadHeader::Capella(payload.execution_payload_header.clone())
            }
            Self::Eip4844(payload) => {
                ExecutionPayloadHeader::Eip4844(payload.execution_payload_header.clone())
            }
        }
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.parent_hash,
            Self::Capella(payload) => payload.execution_payload_header.parent_hash,
            Self::Eip4844(payload) => payload.execution_payload_header.parent_hash,
        }
    }

    fn prev_randao(&self) -> Hash256 {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.prev_randao,
            Self::Capella(payload) => payload.execution_payload_header.prev_randao,
            Self::Eip4844(payload) => payload.execution_payload_header.prev_randao,
        }
    }

    fn block_number(&self) -> u64 {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.block_number,
            Self::Capella(payload) => payload.execution_payload_header.block_number,
            Self::Eip4844(payload) => payload.execution_payload_header.block_number,
        }
    }

    fn timestamp(&self) -> u64 {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.timestamp,
            Self::Capella(payload) => payload.execution_payload_header.timestamp,
            Self::Eip4844(payload) => payload.execution_payload_header.timestamp,
        }
    }

    fn block_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.block_hash,
            Self::Capella(payload) => payload.execution_payload_header.block_hash,
            Self::Eip4844(payload) => payload.execution_payload_header.block_hash,
        }
    }

    fn fee_recipient(&self) -> Address {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.fee_recipient,
            Self::Capella(payload) => payload.execution_payload_header.fee_recipient,
            Self::Eip4844(payload) => payload.execution_payload_header.fee_recipient,
        }
    }

    fn gas_limit(&self) -> u64 {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.gas_limit,
            Self::Capella(payload) => payload.execution_payload_header.gas_limit,
            Self::Eip4844(payload) => payload.execution_payload_header.gas_limit,
        }
    }

    fn transactions(&self) -> Option<&Transactions<T>> {
        None
    }

    // TODO: can this function be optimized?
    fn is_default(&self) -> bool {
        match self {
            Self::Merge(payload) => payload.is_default(),
            Self::Capella(payload) => payload.is_default(),
            Self::Eip4844(payload) => payload.is_default(),
        }
    }
}

// FIXME(sproul): deduplicate this
impl<'b, T: EthSpec> ExecPayload<T> for BlindedPayloadRef<'b, T> {
    fn block_type() -> BlockType {
        BlockType::Blinded
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        match self {
            Self::Merge(payload) => {
                ExecutionPayloadHeader::Merge(payload.execution_payload_header.clone())
            }
            Self::Capella(payload) => {
                ExecutionPayloadHeader::Capella(payload.execution_payload_header.clone())
            }
            Self::Eip4844(payload) => {
                ExecutionPayloadHeader::Eip4844(payload.execution_payload_header.clone())
            }
        }
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.parent_hash,
            Self::Capella(payload) => payload.execution_payload_header.parent_hash,
            Self::Eip4844(payload) => payload.execution_payload_header.parent_hash,
        }
    }

    fn prev_randao(&self) -> Hash256 {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.prev_randao,
            Self::Capella(payload) => payload.execution_payload_header.prev_randao,
            Self::Eip4844(payload) => payload.execution_payload_header.prev_randao,
        }
    }

    fn block_number(&self) -> u64 {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.block_number,
            Self::Capella(payload) => payload.execution_payload_header.block_number,
            Self::Eip4844(payload) => payload.execution_payload_header.block_number,
        }
    }

    fn timestamp(&self) -> u64 {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.timestamp,
            Self::Capella(payload) => payload.execution_payload_header.timestamp,
            Self::Eip4844(payload) => payload.execution_payload_header.timestamp,
        }
    }

    fn block_hash(&self) -> ExecutionBlockHash {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.block_hash,
            Self::Capella(payload) => payload.execution_payload_header.block_hash,
            Self::Eip4844(payload) => payload.execution_payload_header.block_hash,
        }
    }

    fn fee_recipient(&self) -> Address {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.fee_recipient,
            Self::Capella(payload) => payload.execution_payload_header.fee_recipient,
            Self::Eip4844(payload) => payload.execution_payload_header.fee_recipient,
        }
    }

    fn gas_limit(&self) -> u64 {
        match self {
            Self::Merge(payload) => payload.execution_payload_header.gas_limit,
            Self::Capella(payload) => payload.execution_payload_header.gas_limit,
            Self::Eip4844(payload) => payload.execution_payload_header.gas_limit,
        }
    }

    fn transactions(&self) -> Option<&Transactions<T>> {
        None
    }

    // TODO: can this function be optimized?
    fn is_default<'a>(&'a self) -> bool {
        match self {
            Self::Merge(payload) => {
                payload.execution_payload_header == ExecutionPayloadHeaderMerge::default()
            }
            Self::Capella(payload) => {
                payload.execution_payload_header == ExecutionPayloadHeaderCapella::default()
            }
            Self::Eip4844(payload) => {
                payload.execution_payload_header == ExecutionPayloadHeaderEip4844::default()
            }
        }
    }
}

impl<T: EthSpec> ExecPayload<T> for BlindedPayloadMerge<T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        ExecutionPayloadHeader::Merge(ExecutionPayloadHeaderMerge::from(
            self.execution_payload_header.clone(),
        ))
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.execution_payload_header.parent_hash
    }

    fn prev_randao(&self) -> Hash256 {
        self.execution_payload_header.prev_randao
    }

    fn block_number(&self) -> u64 {
        self.execution_payload_header.block_number
    }

    fn timestamp(&self) -> u64 {
        self.execution_payload_header.timestamp
    }

    fn block_hash(&self) -> ExecutionBlockHash {
        self.execution_payload_header.block_hash
    }

    fn fee_recipient(&self) -> Address {
        self.execution_payload_header.fee_recipient
    }

    fn gas_limit(&self) -> u64 {
        self.execution_payload_header.gas_limit
    }

    fn transactions(&self) -> Option<&Transactions<T>> {
        None
    }

    fn is_default(&self) -> bool {
        self.execution_payload_header == ExecutionPayloadHeaderMerge::default()
    }
}
impl<T: EthSpec> ExecPayload<T> for BlindedPayloadCapella<T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        ExecutionPayloadHeader::Capella(ExecutionPayloadHeaderCapella::from(
            self.execution_payload_header.clone(),
        ))
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.execution_payload_header.parent_hash
    }

    fn prev_randao(&self) -> Hash256 {
        self.execution_payload_header.prev_randao
    }

    fn block_number(&self) -> u64 {
        self.execution_payload_header.block_number
    }

    fn timestamp(&self) -> u64 {
        self.execution_payload_header.timestamp
    }

    fn block_hash(&self) -> ExecutionBlockHash {
        self.execution_payload_header.block_hash
    }

    fn fee_recipient(&self) -> Address {
        self.execution_payload_header.fee_recipient
    }

    fn gas_limit(&self) -> u64 {
        self.execution_payload_header.gas_limit
    }

    fn transactions(&self) -> Option<&Transactions<T>> {
        None
    }

    fn is_default(&self) -> bool {
        self.execution_payload_header == ExecutionPayloadHeaderCapella::default()
    }
}
impl<T: EthSpec> ExecPayload<T> for BlindedPayloadEip4844<T> {
    fn block_type() -> BlockType {
        BlockType::Full
    }

    fn to_execution_payload_header(&self) -> ExecutionPayloadHeader<T> {
        ExecutionPayloadHeader::Eip4844(ExecutionPayloadHeaderEip4844::from(
            self.execution_payload_header.clone(),
        ))
    }

    fn parent_hash(&self) -> ExecutionBlockHash {
        self.execution_payload_header.parent_hash
    }

    fn prev_randao(&self) -> Hash256 {
        self.execution_payload_header.prev_randao
    }

    fn block_number(&self) -> u64 {
        self.execution_payload_header.block_number
    }

    fn timestamp(&self) -> u64 {
        self.execution_payload_header.timestamp
    }

    fn block_hash(&self) -> ExecutionBlockHash {
        self.execution_payload_header.block_hash
    }

    fn fee_recipient(&self) -> Address {
        self.execution_payload_header.fee_recipient
    }

    fn gas_limit(&self) -> u64 {
        self.execution_payload_header.gas_limit
    }

    fn transactions(&self) -> Option<&Transactions<T>> {
        None
    }

    fn is_default(&self) -> bool {
        self.execution_payload_header == ExecutionPayloadHeaderEip4844::default()
    }
}

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

//FIXME(sean) fix errors
impl<T: EthSpec> TryInto<BlindedPayloadMerge<T>> for BlindedPayload<T> {
    type Error = ();

    fn try_into(self) -> Result<BlindedPayloadMerge<T>, Self::Error> {
        match self {
            BlindedPayload::Merge(payload) => Ok(payload),
            BlindedPayload::Capella(_) => Err(()),
            BlindedPayload::Eip4844(_) => Err(()),
        }
    }
}
impl<T: EthSpec> TryInto<BlindedPayloadCapella<T>> for BlindedPayload<T> {
    type Error = ();

    fn try_into(self) -> Result<BlindedPayloadCapella<T>, Self::Error> {
        match self {
            BlindedPayload::Merge(_) => Err(()),
            BlindedPayload::Capella(payload) => Ok(payload),
            BlindedPayload::Eip4844(_) => Err(()),
        }
    }
}
impl<T: EthSpec> TryInto<BlindedPayloadEip4844<T>> for BlindedPayload<T> {
    type Error = ();

    fn try_into(self) -> Result<BlindedPayloadEip4844<T>, Self::Error> {
        match self {
            BlindedPayload::Merge(_) => Err(()),
            BlindedPayload::Capella(_) => Err(()),
            BlindedPayload::Eip4844(payload) => Ok(payload),
        }
    }
}

impl<T: EthSpec> Default for FullPayloadMerge<T> {
    fn default() -> Self {
        Self {
            execution_payload: ExecutionPayloadMerge::default(),
        }
    }
}
impl<T: EthSpec> Default for FullPayloadCapella<T> {
    fn default() -> Self {
        Self {
            execution_payload: ExecutionPayloadCapella::default(),
        }
    }
}
impl<T: EthSpec> Default for FullPayloadEip4844<T> {
    fn default() -> Self {
        Self {
            execution_payload: ExecutionPayloadEip4844::default(),
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
/*
impl<T: EthSpec> Default for BlindedPayload<T> {
    fn default() -> Self {
        Self {
            execution_payload_header: ExecutionPayloadHeader::from(&ExecutionPayload::default()),
        }
    }
}
*/

impl<T: EthSpec> Default for BlindedPayloadMerge<T> {
    fn default() -> Self {
        Self {
            execution_payload_header: ExecutionPayloadHeaderMerge::from(
                ExecutionPayloadMerge::default(),
            ),
        }
    }
}

impl<T: EthSpec> Default for BlindedPayloadCapella<T> {
    fn default() -> Self {
        Self {
            execution_payload_header: ExecutionPayloadHeaderCapella::from(
                ExecutionPayloadCapella::default(),
            ),
        }
    }
}

impl<T: EthSpec> Default for BlindedPayloadEip4844<T> {
    fn default() -> Self {
        Self {
            execution_payload_header: ExecutionPayloadHeaderEip4844::from(
                ExecutionPayloadEip4844::default(),
            ),
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

impl<T: EthSpec> From<ExecutionPayloadHeaderMerge<T>> for BlindedPayloadMerge<T> {
    fn from(execution_payload_header: ExecutionPayloadHeaderMerge<T>) -> Self {
        Self {
            execution_payload_header,
        }
    }
}
impl<T: EthSpec> From<ExecutionPayloadHeaderCapella<T>> for BlindedPayloadCapella<T> {
    fn from(execution_payload_header: ExecutionPayloadHeaderCapella<T>) -> Self {
        Self {
            execution_payload_header,
        }
    }
}
impl<T: EthSpec> From<ExecutionPayloadHeaderEip4844<T>> for BlindedPayloadEip4844<T> {
    fn from(execution_payload_header: ExecutionPayloadHeaderEip4844<T>) -> Self {
        Self {
            execution_payload_header,
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

// FIXME(sproul): consider adding references to these From impls
impl<T: EthSpec> From<ExecutionPayloadMerge<T>> for BlindedPayloadMerge<T> {
    fn from(execution_payload: ExecutionPayloadMerge<T>) -> Self {
        Self {
            execution_payload_header: ExecutionPayloadHeaderMerge::from(execution_payload),
        }
    }
}
impl<T: EthSpec> From<ExecutionPayloadCapella<T>> for BlindedPayloadCapella<T> {
    fn from(execution_payload: ExecutionPayloadCapella<T>) -> Self {
        Self {
            execution_payload_header: ExecutionPayloadHeaderCapella::from(execution_payload),
        }
    }
}
impl<T: EthSpec> From<ExecutionPayloadEip4844<T>> for BlindedPayloadEip4844<T> {
    fn from(execution_payload: ExecutionPayloadEip4844<T>) -> Self {
        Self {
            execution_payload_header: ExecutionPayloadHeaderEip4844::from(execution_payload),
        }
    }
}

impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for BlindedPayloadMerge<T> {
    type Error = ();
    fn try_from(header: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
        match header {
            ExecutionPayloadHeader::Merge(execution_payload_header) => {
                Ok(execution_payload_header.into())
            }
            _ => Err(()),
        }
    }
}
impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for BlindedPayloadCapella<T> {
    type Error = ();
    fn try_from(header: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
        match header {
            ExecutionPayloadHeader::Capella(execution_payload_header) => {
                Ok(execution_payload_header.into())
            }
            _ => Err(()),
        }
    }
}

impl<T: EthSpec> TryFrom<ExecutionPayloadHeader<T>> for BlindedPayloadEip4844<T> {
    type Error = ();
    fn try_from(header: ExecutionPayloadHeader<T>) -> Result<Self, Self::Error> {
        match header {
            ExecutionPayloadHeader::Eip4844(execution_payload_header) => {
                Ok(execution_payload_header.into())
            }
            _ => Err(()),
        }
    }
}

/*
impl<T: EthSpec> Decode for BlindedPayload<T> {
    fn is_ssz_fixed_len() -> bool {
        <ExecutionPayloadHeader<T> as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <ExecutionPayloadHeader<T> as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            execution_payload_header: ExecutionPayloadHeader::from_ssz_bytes(bytes)?,
        })
    }
}
 */

/*
impl<T: EthSpec> Encode for BlindedPayload<T> {
    fn is_ssz_fixed_len() -> bool {
        <ExecutionPayloadHeader<T> as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.execution_payload_header.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.execution_payload_header.ssz_bytes_len()
    }
}
*/

/*
impl<T: EthSpec> TreeHash for FullPayload<T> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <ExecutionPayload<T>>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        self.execution_payload.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <ExecutionPayload<T>>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.execution_payload.tree_hash_root()
    }
}
*/

/*
impl<T: EthSpec> Decode for FullPayload<T> {
    fn is_ssz_fixed_len() -> bool {
        <ExecutionPayload<T> as Decode>::is_ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(FullPayload {
            execution_payload: Decode::from_ssz_bytes(bytes)?,
        })
    }
}

impl<T: EthSpec> Encode for FullPayload<T> {
    fn is_ssz_fixed_len() -> bool {
        <ExecutionPayload<T> as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.execution_payload.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.execution_payload.ssz_bytes_len()
    }
}
*/
