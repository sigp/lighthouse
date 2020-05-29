mod checkpoint_manager;
mod fork_choice_store;

use crate::{errors::BeaconChainError, metrics, BeaconChain, BeaconChainTypes};
use checkpoint_manager::{get_effective_balances, CheckpointManager, CheckpointWithBalances};
use fork_choice_store::ForkChoiceStore;
use lmd_ghost::ForkChoiceStore as ForkChoiceStoreTrait;
use parking_lot::{RwLock, RwLockReadGuard};
use proto_array_fork_choice::{core::ProtoArray, ProtoArrayForkChoice};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::common::get_indexed_attestation;
use std::marker::PhantomData;
use store::{DBColumn, Error as StoreError, SimpleStoreItem};
use types::{
    BeaconBlock, BeaconState, BeaconStateError, Epoch, EthSpec, Hash256, IndexedAttestation, Slot,
};

type Result<T> = std::result::Result<T, Error>;

type LmdGhost<T: BeaconChainTypes> = lmd_ghost::ForkChoice<ForkChoiceStore<T>, T::EthSpec>;

#[derive(Debug)]
pub enum Error {
    MissingBlock(Hash256),
    MissingState(Hash256),
    BackendError(String),
    BeaconStateError(BeaconStateError),
    StoreError(StoreError),
    BeaconChainError(Box<BeaconChainError>),
    UnknownBlockSlot(Hash256),
    UnknownJustifiedBlock(Hash256),
    UnknownJustifiedState(Hash256),
    UnableToJsonEncode(String),
    InvalidAttestation,
}

pub struct ForkChoice<T: BeaconChainTypes> {
    backend: LmdGhost<T>,
    /// Used for resolving the `0x00..00` alias back to genesis.
    ///
    /// Does not necessarily need to be the _actual_ genesis, it suffices to be the finalized root
    /// whenever the struct was instantiated.
    genesis_block_root: Hash256,
}

/*
impl<T: BeaconChainTypes> PartialEq for ForkChoice<T> {
    /// This implementation ignores the `store`.
    fn eq(&self, other: &Self) -> bool {
        self.backend == other.backend
            && self.genesis_block_root == other.genesis_block_root
            && *self.checkpoint_manager.read() == *other.checkpoint_manager.read()
    }
}
*/

impl<T: BeaconChainTypes> ForkChoice<T> {
    /// Instantiate a new fork chooser.
    ///
    /// "Genesis" does not necessarily need to be the absolute genesis, it can be some finalized
    /// block.
    pub fn new(
        backend: LmdGhost<T>,
        genesis_block_root: Hash256,
        genesis_state: &BeaconState<T::EthSpec>,
    ) -> Self {
        Self {
            backend,
            genesis_block_root,
        }
    }

    /// Run the fork choice rule to determine the head.
    pub fn find_head(&self) -> Result<Hash256> {
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_FIND_HEAD_TIMES);
        self.backend.find_head()
    }

    /// Returns true if the given block is known to fork choice.
    pub fn contains_block(&self, block_root: &Hash256) -> bool {
        self.backend.proto_array().contains_block(block_root)
    }

    /// Returns the state root for the given block root.
    pub fn block_slot_and_state_root(&self, block_root: &Hash256) -> Option<(Slot, Hash256)> {
        self.backend
            .proto_array()
            .block_slot_and_state_root(block_root)
    }

    /// Process all attestations in the given `block`.
    ///
    /// Assumes the block (and therefore its attestations) are valid. It is a logic error to
    /// provide an invalid block.
    pub fn process_block(
        &self,
        state: &BeaconState<T::EthSpec>,
        block: &BeaconBlock<T::EthSpec>,
        block_root: Hash256,
    ) -> Result<()> {
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_BLOCK_TIMES);

        self.backend.on_block(block, block_root, state)?;

        Ok(())
    }

    /// Process an attestation which references `block` in `attestation.data.beacon_block_root`.
    ///
    /// Assumes the attestation is valid.
    pub fn process_indexed_attestation(
        &self,
        attestation: &IndexedAttestation<T::EthSpec>,
    ) -> Result<()> {
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_ATTESTATION_TIMES);

        self.backend.on_attestation(attestation)?;

        Ok(())
    }

    /// Returns the latest message for a given validator, if any.
    ///
    /// Returns `(block_root, block_slot)`.
    pub fn latest_message(&self, validator_index: usize) -> Option<(Hash256, Epoch)> {
        self.backend.proto_array().latest_message(validator_index)
    }

    /// Trigger a prune on the underlying fork choice backend.
    pub fn prune(&self) -> Result<()> {
        self.backend.prune().map_err(Into::into)
    }

    /// Returns a read-lock to the core `ProtoArray` struct.
    ///
    /// Should only be used when encoding/decoding during troubleshooting.
    pub fn core_proto_array(&self) -> RwLockReadGuard<ProtoArray> {
        self.backend.proto_array().core_proto_array()
    }

    /// Returns a `SszForkChoice` which contains the current state of `Self`.
    pub fn as_ssz_container(&self) -> SszForkChoice {
        SszForkChoice {
            genesis_block_root: self.genesis_block_root.clone(),
            checkpoint_manager: self.checkpoint_manager.read().clone(),
            backend_bytes: self.backend.as_bytes(),
        }
    }

    /// Instantiates `Self` from a prior `SszForkChoice`.
    ///
    /// The created `Self` will have the same state as the `Self` that created the `SszForkChoice`.
    pub fn from_ssz_container(ssz_container: SszForkChoice) -> Result<Self> {
        let backend = ProtoArrayForkChoice::from_bytes(&ssz_container.backend_bytes)?;

        Ok(Self {
            backend,
            genesis_block_root: ssz_container.genesis_block_root,
            checkpoint_manager: RwLock::new(ssz_container.checkpoint_manager),
            _phantom: PhantomData,
        })
    }
}

/// Helper struct that is used to encode/decode the state of the `ForkChoice` as SSZ bytes.
///
/// This is used when persisting the state of the `BeaconChain` to disk.
#[derive(Encode, Decode, Clone)]
pub struct SszForkChoice {
    genesis_block_root: Hash256,
    checkpoint_manager: CheckpointManager,
    backend_bytes: Vec<u8>,
}

impl<T, E> From<lmd_ghost::Error<T, E>> for Error
where
    T: lmd_ghost::ForkChoiceStore<E> + std::fmt::Debug,
    E: EthSpec,
    T::Error: std::fmt::Debug,
{
    fn from(e: lmd_ghost::Error<T, E>) -> Error {
        Error::BackendError(format!("{:?}", e))
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Error {
        Error::BeaconChainError(Box::new(e))
    }
}

impl From<StoreError> for Error {
    fn from(e: StoreError) -> Error {
        Error::StoreError(e)
    }
}

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::BackendError(e)
    }
}

impl SimpleStoreItem for SszForkChoice {
    fn db_column() -> DBColumn {
        DBColumn::ForkChoice
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> std::result::Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
