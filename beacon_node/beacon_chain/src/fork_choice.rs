mod fork_choice_store;

use crate::{errors::BeaconChainError, metrics, BeaconChainTypes, BeaconSnapshot};
use fork_choice_store::{Error as ForkChoiceStoreError, ForkChoiceStore};
use lmd_ghost::Error as LmdGhostError;
use parking_lot::{RwLock, RwLockReadGuard};
use proto_array_fork_choice::{core::ProtoArray, ProtoArrayForkChoice};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use store::{DBColumn, Error as StoreError, SimpleStoreItem};
use types::{
    BeaconBlock, BeaconState, BeaconStateError, ChainSpec, Epoch, Hash256, IndexedAttestation, Slot,
};

type Result<T> = std::result::Result<T, Error>;
type LmdGhost<T> = lmd_ghost::ForkChoice<ForkChoiceStore<T>, <T as BeaconChainTypes>::EthSpec>;

#[derive(Debug)]
pub enum Error {
    MissingBlock(Hash256),
    MissingState(Hash256),
    BackendError(LmdGhostError<ForkChoiceStoreError>),
    ForkChoiceStoreError(ForkChoiceStoreError),
    BeaconStateError(BeaconStateError),
    StoreError(StoreError),
    BeaconChainError(Box<BeaconChainError>),
    UnknownBlockSlot(Hash256),
    UnknownJustifiedBlock(Hash256),
    UnknownJustifiedState(Hash256),
    UnableToJsonEncode(String),
    InvalidAttestation,
    InvalidPersistedBytes(ssz::DecodeError),
    InvalidProtoArrayBytes(String),
    InvalidForkChoiceStoreBytes(ForkChoiceStoreError),
}

pub struct ForkChoice<T: BeaconChainTypes> {
    backend: RwLock<LmdGhost<T>>,
}

impl<T: BeaconChainTypes> PartialEq for ForkChoice<T> {
    fn eq(&self, other: &Self) -> bool {
        *self.backend.read() == *other.backend.read()
    }
}

impl<T: BeaconChainTypes> ForkChoice<T> {
    /// Instantiate a new fork chooser.
    ///
    /// "Genesis" does not necessarily need to be the absolute genesis, it can be some finalized
    /// block.
    pub fn from_genesis(
        store: Arc<T::Store>,
        slot_clock: T::SlotClock,
        genesis: &BeaconSnapshot<T::EthSpec>,
        spec: &ChainSpec,
    ) -> Result<Self> {
        let fc_store = ForkChoiceStore::from_genesis(store, slot_clock, genesis, spec)
            .map_err(Error::ForkChoiceStoreError)?;

        let backend = LmdGhost::from_genesis(
            fc_store,
            genesis.beacon_block_root,
            &genesis.beacon_block.message,
            &genesis.beacon_state,
        )?;

        Ok(Self {
            backend: RwLock::new(backend),
        })
    }

    /// Run the fork choice rule to determine the head.
    pub fn find_head(&self) -> Result<Hash256> {
        let _timer = metrics::start_timer(&metrics::FORK_CHOICE_FIND_HEAD_TIMES);
        self.backend.write().find_head().map_err(Into::into)
    }

    /// Returns true if the given block is known to fork choice.
    pub fn contains_block(&self, block_root: &Hash256) -> bool {
        self.backend.read().proto_array().contains_block(block_root)
    }

    /// Returns the state root for the given block root.
    pub fn block_slot_and_state_root(&self, block_root: &Hash256) -> Option<(Slot, Hash256)> {
        self.backend
            .read()
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
        let _timer = metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_BLOCK_TIMES);

        self.backend.write().on_block(block, block_root, state)?;

        Ok(())
    }

    /// Process an attestation which references `block` in `attestation.data.beacon_block_root`.
    ///
    /// Assumes the attestation is valid.
    pub fn process_indexed_attestation(
        &self,
        attestation: &IndexedAttestation<T::EthSpec>,
    ) -> Result<()> {
        let _timer = metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_ATTESTATION_TIMES);

        self.backend.write().on_attestation(attestation)?;

        Ok(())
    }

    /// Returns the latest message for a given validator, if any.
    ///
    /// Returns `(block_root, block_slot)`.
    pub fn latest_message(&self, validator_index: usize) -> Option<(Hash256, Epoch)> {
        self.backend
            .read()
            .proto_array()
            .latest_message(validator_index)
    }

    /// Trigger a prune on the underlying fork choice backend.
    pub fn prune(&self) -> Result<()> {
        self.backend.write().prune().map_err(Into::into)
    }

    /// Returns a read-lock to the core `ProtoArray` struct.
    ///
    /// Should only be used when encoding/decoding during troubleshooting.
    pub fn core_proto_array(&self) -> RwLockReadGuard<ProtoArray> {
        todo!()
        // self.backend.read().proto_array().core_proto_array()
    }

    pub fn from_persisted(
        persisted: &PersistedForkChoice,
        store: Arc<T::Store>,
        slot_clock: T::SlotClock,
    ) -> Result<Self> {
        let fc_store = ForkChoiceStore::from_bytes(&persisted.fc_store_bytes, store, slot_clock)
            .map_err(Error::InvalidForkChoiceStoreBytes)?;
        let proto_array = ProtoArrayForkChoice::from_bytes(&persisted.proto_array_bytes)
            .map_err(Error::InvalidProtoArrayBytes)?;

        Ok(Self {
            backend: RwLock::new(LmdGhost::from_components(
                fc_store,
                proto_array,
                persisted.genesis_block_root,
            )),
        })
    }

    pub fn to_persisted(&self) -> PersistedForkChoice {
        let backend = self.backend.read();

        PersistedForkChoice {
            fc_store_bytes: backend.fc_store().to_bytes(),
            proto_array_bytes: backend.proto_array().as_bytes(),
            genesis_block_root: *backend.genesis_block_root(),
        }
    }
}

impl From<LmdGhostError<ForkChoiceStoreError>> for Error {
    fn from(e: LmdGhostError<ForkChoiceStoreError>) -> Error {
        Error::BackendError(e)
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

/// Helper struct that is used to encode/decode the state of the `ForkChoice` as SSZ bytes.
///
/// This is used when persisting the state of the `BeaconChain` to disk.
#[derive(Encode, Decode, Clone)]
pub struct PersistedForkChoice {
    pub(crate) fc_store_bytes: Vec<u8>,
    pub(crate) proto_array_bytes: Vec<u8>,
    pub(crate) genesis_block_root: Hash256,
}

impl SimpleStoreItem for PersistedForkChoice {
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
