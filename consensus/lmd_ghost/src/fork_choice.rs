use crate::ForkChoiceStore;
use proto_array_fork_choice::ProtoArrayForkChoice;
use std::marker::PhantomData;
use types::{BeaconBlock, BeaconState, Epoch, EthSpec, Hash256, IndexedAttestation, Slot};

const SAFE_SLOTS_TO_UPDATE_JUSTIFIED: u64 = 8;

#[derive(Debug)]
pub enum Error<T> {
    // TODO: make this an actual error enum.
    ProtoArrayError(String),
    ForkChoiceStoreError(T),
}

impl<T> From<String> for Error<T> {
    fn from(e: String) -> Self {
        Error::ProtoArrayError(e)
    }
}

/// Calculate how far `slot` lies from the start of its epoch.
pub fn compute_slots_since_epoch_start<E: EthSpec>(slot: Slot) -> Slot {
    slot - slot
        .epoch(E::slots_per_epoch())
        .start_slot(E::slots_per_epoch())
}

fn compute_start_slot_at_epoch<E: EthSpec>(epoch: Epoch) -> Slot {
    epoch.start_slot(E::slots_per_epoch())
}

pub struct ForkChoice<T, E> {
    /// Storage for `ForkChoice`, modelled off the spec `Store` object.
    fc_store: T,
    /// The underlying representation of the block DAG.
    proto_array: ProtoArrayForkChoice,
    /// Used for resolving the `0x00..00` alias back to genesis.
    ///
    /// Does not necessarily need to be the _actual_ genesis, it suffices to be the finalized root
    /// whenever the struct was instantiated.
    genesis_block_root: Hash256,
    _phantom: PhantomData<E>,
}

impl<T, E> PartialEq for ForkChoice<T, E>
where
    T: ForkChoiceStore<E> + PartialEq,
    E: EthSpec,
{
    fn eq(&self, other: &Self) -> bool {
        self.fc_store == other.fc_store
            && self.proto_array == other.proto_array
            && self.genesis_block_root == other.genesis_block_root
    }
}

impl<T, E> ForkChoice<T, E>
where
    T: ForkChoiceStore<E>,
    E: EthSpec,
{
    pub fn from_genesis(
        fc_store: T,
        genesis_block_root: Hash256,
        genesis_block: &BeaconBlock<E>,
        genesis_state: &BeaconState<E>,
    ) -> Result<Self, Error<T::Error>> {
        let finalized_block_slot = genesis_block.slot;
        let finalized_block_state_root = genesis_block.state_root;
        let justified_epoch = genesis_state.current_epoch();
        let finalized_epoch = genesis_state.current_epoch();
        let finalized_root = genesis_block_root;

        let proto_array = ProtoArrayForkChoice::new(
            finalized_block_slot,
            finalized_block_state_root,
            justified_epoch,
            finalized_epoch,
            finalized_root,
        )?;

        Ok(Self {
            fc_store,
            proto_array,
            genesis_block_root,
            _phantom: PhantomData,
        })
    }

    pub fn from_components(
        fc_store: T,
        proto_array: ProtoArrayForkChoice,
        genesis_block_root: Hash256,
    ) -> Self {
        Self {
            fc_store,
            proto_array,
            genesis_block_root,
            _phantom: PhantomData,
        }
    }

    /// Run the fork choice rule to determine the head.
    pub fn find_head(&mut self) -> Result<Hash256, Error<T::Error>> {
        self.fc_store
            .update_time()
            .map_err(Error::ForkChoiceStoreError)?;

        let store = &mut self.fc_store;
        let genesis_block_root = self.genesis_block_root;

        let remove_alias = |root| {
            if root == Hash256::zero() {
                genesis_block_root
            } else {
                root
            }
        };

        let result = self
            .proto_array
            .find_head(
                store.justified_checkpoint().epoch,
                remove_alias(store.justified_checkpoint().root),
                store.finalized_checkpoint().epoch,
                store.justified_balances(),
            )
            .map_err(Into::into);

        result
    }

    pub fn on_attestation(
        &mut self,
        attestation: &IndexedAttestation<E>,
    ) -> Result<(), Error<T::Error>> {
        self.fc_store
            .update_time()
            .map_err(Error::ForkChoiceStoreError)?;

        // Ensure the store is up-to-date.
        let block_hash = attestation.data.beacon_block_root;

        // Ignore any attestations to the zero hash.
        //
        // This is an edge case that results from the spec aliasing the zero hash to the genesis
        // block. Attesters may attest to the zero hash if they have never seen a block.
        //
        // We have two options here:
        //
        //  1. Apply all zero-hash attestations to the zero hash.
        //  2. Ignore all attestations to the zero hash.
        //
        // (1) becomes weird once we hit finality and fork choice drops the genesis block. (2) is
        // fine because votes to the genesis block are not useful; all validators implicitly attest
        // to genesis just by being present in the chain.
        //
        // Additionally, don't add any block hash to fork choice unless we have imported the block.
        if block_hash != Hash256::zero() {
            for validator_index in attestation.attesting_indices.iter() {
                self.proto_array.process_attestation(
                    *validator_index as usize,
                    block_hash,
                    attestation.data.target.epoch,
                )?;
            }
        }

        Ok(())
    }

    pub fn on_block(
        &mut self,
        block: &BeaconBlock<E>,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error<T::Error>> {
        self.fc_store
            .update_time()
            .map_err(Error::ForkChoiceStoreError)?;

        let store = &mut self.fc_store;

        // TODO: stuff here
        if state.current_justified_checkpoint.epoch > store.justified_checkpoint().epoch {
            if state.current_justified_checkpoint.epoch > store.best_justified_checkpoint().epoch {
                store.set_best_justified_checkpoint(state);
            }
            if Self::should_update_justified_checkpoint(store, state)
                .map_err(Error::ForkChoiceStoreError)?
            {
                store.set_justified_checkpoint(state);
            }
        }

        if state.finalized_checkpoint.epoch > store.finalized_checkpoint().epoch {
            store.set_finalized_checkpoint(state.finalized_checkpoint);
            let finalized_slot =
                compute_start_slot_at_epoch::<E>(store.finalized_checkpoint().epoch);

            if state.current_justified_checkpoint.epoch > store.justified_checkpoint().epoch
                || store
                    .get_ancestor(state, store.justified_checkpoint().root, finalized_slot)
                    .map_err(Error::ForkChoiceStoreError)?
                    != store.finalized_checkpoint().root
            {
                store.set_justified_checkpoint(state);
            }
        }

        // This does not apply a vote to the block, it just makes fork choice aware of the block so
        // it can still be identified as the head even if it doesn't have any votes.
        self.proto_array.process_block(
            block.slot,
            block_root,
            block.parent_root,
            block.state_root,
            state.current_justified_checkpoint.epoch,
            state.finalized_checkpoint.epoch,
        )?;

        Ok(())
    }

    fn should_update_justified_checkpoint(
        store: &T,
        state: &BeaconState<E>,
    ) -> Result<bool, T::Error> {
        let new_justified_checkpoint = &state.current_justified_checkpoint;

        if compute_slots_since_epoch_start::<E>(store.get_current_slot())
            < SAFE_SLOTS_TO_UPDATE_JUSTIFIED
        {
            return Ok(true);
        }

        let justified_slot = compute_start_slot_at_epoch::<E>(store.justified_checkpoint().epoch);
        if store.get_ancestor(state, new_justified_checkpoint.root, justified_slot)?
            != store.justified_checkpoint().root
        {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn proto_array(&self) -> &ProtoArrayForkChoice {
        &self.proto_array
    }

    pub fn fc_store(&self) -> &T {
        &self.fc_store
    }

    pub fn genesis_block_root(&self) -> &Hash256 {
        &self.genesis_block_root
    }

    pub fn prune(&mut self) -> Result<(), Error<T::Error>> {
        let finalized_root = self.fc_store.finalized_checkpoint().root;

        self.proto_array
            .maybe_prune(finalized_root)
            .map_err(Into::into)
    }
}
