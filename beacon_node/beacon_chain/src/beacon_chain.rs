use crate::attestation_aggregator::{AttestationAggregator, Outcome as AggregationOutcome};
use crate::checkpoint::CheckPoint;
use crate::errors::{BeaconChainError as Error, BlockProductionError};
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    ClientDB, DBError,
};
use fork_choice::{ForkChoice, ForkChoiceError};
use log::{debug, trace};
use parking_lot::{RwLock, RwLockReadGuard};
use slot_clock::SlotClock;
use ssz::ssz_encode;
use state_processing::{
    per_block_processing, per_block_processing_without_verifying_block_signature,
    per_slot_processing, BlockProcessingError, SlotProcessingError,
};
use std::sync::Arc;
use types::*;

#[derive(Debug, PartialEq)]
pub enum ValidBlock {
    /// The block was successfully processed.
    Processed,
}

#[derive(Debug, PartialEq)]
pub enum InvalidBlock {
    /// The block slot is greater than the present slot.
    FutureSlot,
    /// The block state_root does not match the generated state.
    StateRootMismatch,
    /// The blocks parent_root is unknown.
    ParentUnknown,
    /// There was an error whilst advancing the parent state to the present slot. This condition
    /// should not occur, it likely represents an internal error.
    SlotProcessingError(SlotProcessingError),
    /// The block could not be applied to the state, it is invalid.
    PerBlockProcessingError(BlockProcessingError),
}

#[derive(Debug, PartialEq)]
pub enum BlockProcessingOutcome {
    /// The block was successfully validated.
    ValidBlock(ValidBlock),
    /// The block was not successfully validated.
    InvalidBlock(InvalidBlock),
}

pub struct BeaconChain<T: ClientDB + Sized, U: SlotClock, F: ForkChoice> {
    pub block_store: Arc<BeaconBlockStore<T>>,
    pub state_store: Arc<BeaconStateStore<T>>,
    pub slot_clock: U,
    pub attestation_aggregator: RwLock<AttestationAggregator>,
    pub deposits_for_inclusion: RwLock<Vec<Deposit>>,
    pub exits_for_inclusion: RwLock<Vec<VoluntaryExit>>,
    pub transfers_for_inclusion: RwLock<Vec<Transfer>>,
    pub proposer_slashings_for_inclusion: RwLock<Vec<ProposerSlashing>>,
    pub attester_slashings_for_inclusion: RwLock<Vec<AttesterSlashing>>,
    canonical_head: RwLock<CheckPoint>,
    finalized_head: RwLock<CheckPoint>,
    pub state: RwLock<BeaconState>,
    pub spec: ChainSpec,
    pub fork_choice: RwLock<F>,
}

impl<T, U, F> BeaconChain<T, U, F>
where
    T: ClientDB,
    U: SlotClock,
    F: ForkChoice,
{
    /// Instantiate a new Beacon Chain, from genesis.
    pub fn from_genesis(
        state_store: Arc<BeaconStateStore<T>>,
        block_store: Arc<BeaconBlockStore<T>>,
        slot_clock: U,
        mut genesis_state: BeaconState,
        genesis_block: BeaconBlock,
        spec: ChainSpec,
        fork_choice: F,
    ) -> Result<Self, Error> {
        let state_root = genesis_state.canonical_root();
        state_store.put(&state_root, &ssz_encode(&genesis_state)[..])?;

        let block_root = genesis_block.into_header().canonical_root();
        block_store.put(&block_root, &ssz_encode(&genesis_block)[..])?;

        let finalized_head = RwLock::new(CheckPoint::new(
            genesis_block.clone(),
            block_root,
            genesis_state.clone(),
            state_root,
        ));
        let canonical_head = RwLock::new(CheckPoint::new(
            genesis_block.clone(),
            block_root,
            genesis_state.clone(),
            state_root,
        ));
        let attestation_aggregator = RwLock::new(AttestationAggregator::new());

        genesis_state.build_epoch_cache(RelativeEpoch::Previous, &spec)?;
        genesis_state.build_epoch_cache(RelativeEpoch::Current, &spec)?;
        genesis_state.build_epoch_cache(RelativeEpoch::NextWithoutRegistryChange, &spec)?;
        genesis_state.build_epoch_cache(RelativeEpoch::NextWithRegistryChange, &spec)?;

        Ok(Self {
            block_store,
            state_store,
            slot_clock,
            attestation_aggregator,
            deposits_for_inclusion: RwLock::new(vec![]),
            exits_for_inclusion: RwLock::new(vec![]),
            transfers_for_inclusion: RwLock::new(vec![]),
            proposer_slashings_for_inclusion: RwLock::new(vec![]),
            attester_slashings_for_inclusion: RwLock::new(vec![]),
            state: RwLock::new(genesis_state),
            finalized_head,
            canonical_head,
            spec,
            fork_choice: RwLock::new(fork_choice),
        })
    }

    /// Update the canonical head to some new values.
    pub fn update_canonical_head(
        &self,
        new_beacon_block: BeaconBlock,
        new_beacon_block_root: Hash256,
        new_beacon_state: BeaconState,
        new_beacon_state_root: Hash256,
    ) {
        debug!(
            "Updating canonical head with block at slot: {}",
            new_beacon_block.slot
        );
        let mut head = self.canonical_head.write();
        head.update(
            new_beacon_block,
            new_beacon_block_root,
            new_beacon_state,
            new_beacon_state_root,
        );
    }

    /// Returns a read-lock guarded `CheckPoint` struct for reading the head (as chosen by the
    /// fork-choice rule).
    ///
    /// It is important to note that the `beacon_state` returned may not match the present slot. It
    /// is the state as it was when the head block was recieved, which could be some slots prior to
    /// now.
    pub fn head(&self) -> RwLockReadGuard<CheckPoint> {
        self.canonical_head.read()
    }

    /// Update the justified head to some new values.
    pub fn update_finalized_head(
        &self,
        new_beacon_block: BeaconBlock,
        new_beacon_block_root: Hash256,
        new_beacon_state: BeaconState,
        new_beacon_state_root: Hash256,
    ) {
        let mut finalized_head = self.finalized_head.write();
        finalized_head.update(
            new_beacon_block,
            new_beacon_block_root,
            new_beacon_state,
            new_beacon_state_root,
        );
    }

    /// Returns a read-lock guarded `CheckPoint` struct for reading the justified head (as chosen,
    /// indirectly,  by the fork-choice rule).
    pub fn finalized_head(&self) -> RwLockReadGuard<CheckPoint> {
        self.finalized_head.read()
    }

    /// Advance the `self.state` `BeaconState` to the supplied slot.
    ///
    /// This will perform per_slot and per_epoch processing as required.
    ///
    /// The `previous_block_root` will be set to the root of the current head block (as determined
    /// by the fork-choice rule).
    ///
    /// It is important to note that this is _not_ the state corresponding to the canonical head
    /// block, instead it is that state which may or may not have had additional per slot/epoch
    /// processing applied to it.
    pub fn advance_state(&self, slot: Slot) -> Result<(), SlotProcessingError> {
        let state_slot = self.state.read().slot;

        let latest_block_header = self.head().beacon_block.into_header();

        for _ in state_slot.as_u64()..slot.as_u64() {
            per_slot_processing(&mut *self.state.write(), &latest_block_header, &self.spec)?;
        }

        Ok(())
    }

    /// Returns the validator index (if any) for the given public key.
    ///
    /// Information is retrieved from the present `beacon_state.validator_registry`.
    pub fn validator_index(&self, pubkey: &PublicKey) -> Option<usize> {
        for (i, validator) in self
            .head()
            .beacon_state
            .validator_registry
            .iter()
            .enumerate()
        {
            if validator.pubkey == *pubkey {
                return Some(i);
            }
        }
        None
    }

    /// Reads the slot clock, returns `None` if the slot is unavailable.
    ///
    /// The slot might be unavailable due to an error with the system clock, or if the present time
    /// is before genesis (i.e., a negative slot).
    ///
    /// This is distinct to `present_slot`, which simply reads the latest state. If a
    /// call to `read_slot_clock` results in a higher slot than a call to `present_slot`,
    /// `self.state` should undergo per slot processing.
    pub fn read_slot_clock(&self) -> Option<Slot> {
        match self.slot_clock.present_slot() {
            Ok(Some(some_slot)) => Some(some_slot),
            Ok(None) => None,
            _ => None,
        }
    }

    /// Returns slot of the present state.
    ///
    /// This is distinct to `read_slot_clock`, which reads from the actual system clock. If
    /// `self.state` has not been transitioned it is possible for the system clock to be on a
    /// different slot to what is returned from this call.
    pub fn present_slot(&self) -> Slot {
        self.state.read().slot
    }

    /// Returns the block proposer for a given slot.
    ///
    /// Information is read from the present `beacon_state` shuffling, so only information from the
    /// present and prior epoch is available.
    pub fn block_proposer(&self, slot: Slot) -> Result<usize, BeaconStateError> {
        trace!("BeaconChain::block_proposer: slot: {}", slot);
        let index = self.state.read().get_beacon_proposer_index(
            slot,
            RelativeEpoch::Current,
            &self.spec,
        )?;

        Ok(index)
    }

    /// Returns the attestation slot and shard for a given validator index.
    ///
    /// Information is read from the current state, so only information from the present and prior
    /// epoch is available.
    pub fn validator_attestion_slot_and_shard(
        &self,
        validator_index: usize,
    ) -> Result<Option<(Slot, u64)>, BeaconStateError> {
        trace!(
            "BeaconChain::validator_attestion_slot_and_shard: validator_index: {}",
            validator_index
        );
        if let Some(attestation_duty) = self
            .state
            .read()
            .get_attestation_duties(validator_index, &self.spec)?
        {
            Ok(Some((attestation_duty.slot, attestation_duty.shard)))
        } else {
            Ok(None)
        }
    }

    /// Produce an `AttestationData` that is valid for the present `slot` and given `shard`.
    pub fn produce_attestation_data(&self, shard: u64) -> Result<AttestationData, Error> {
        trace!("BeaconChain::produce_attestation_data: shard: {}", shard);
        let source_epoch = self.state.read().current_justified_epoch;
        let source_root = *self.state.read().get_block_root(
            source_epoch.start_slot(self.spec.slots_per_epoch),
            &self.spec,
        )?;

        let target_root = *self.state.read().get_block_root(
            self.state
                .read()
                .slot
                .epoch(self.spec.slots_per_epoch)
                .start_slot(self.spec.slots_per_epoch),
            &self.spec,
        )?;

        Ok(AttestationData {
            slot: self.state.read().slot,
            shard,
            beacon_block_root: self.head().beacon_block_root,
            target_root,
            crosslink_data_root: Hash256::zero(),
            previous_crosslink: Crosslink {
                epoch: self.state.read().slot.epoch(self.spec.slots_per_epoch),
                crosslink_data_root: Hash256::zero(),
            },
            source_epoch,
            source_root,
        })
    }

    /// Validate a `FreeAttestation` and either:
    ///
    /// - Create a new `Attestation`.
    /// - Aggregate it to an existing `Attestation`.
    pub fn process_free_attestation(
        &self,
        free_attestation: FreeAttestation,
    ) -> Result<AggregationOutcome, Error> {
        let aggregation_outcome = self
            .attestation_aggregator
            .write()
            .process_free_attestation(&self.state.read(), &free_attestation, &self.spec)?;

        // return if the attestation is invalid
        if !aggregation_outcome.valid {
            return Ok(aggregation_outcome);
        }

        // valid attestation, proceed with fork-choice logic
        self.fork_choice.write().add_attestation(
            free_attestation.validator_index,
            &free_attestation.data.beacon_block_root,
            &self.spec,
        )?;
        Ok(aggregation_outcome)
    }

    /// Accept some deposit and queue it for inclusion in an appropriate block.
    pub fn receive_deposit_for_inclusion(&self, deposit: Deposit) {
        // TODO: deposits are not checked for validity; check them.
        //
        // https://github.com/sigp/lighthouse/issues/276
        self.deposits_for_inclusion.write().push(deposit);
    }

    /// Return a vec of deposits suitable for inclusion in some block.
    pub fn get_deposits_for_block(&self) -> Vec<Deposit> {
        // TODO: deposits are indiscriminately included; check them for validity.
        //
        // https://github.com/sigp/lighthouse/issues/275
        self.deposits_for_inclusion.read().clone()
    }

    /// Takes a list of `Deposits` that were included in recent blocks and removes them from the
    /// inclusion queue.
    ///
    /// This ensures that `Deposits` are not included twice in successive blocks.
    pub fn set_deposits_as_included(&self, included_deposits: &[Deposit]) {
        // TODO: method does not take forks into account; consider this.
        //
        // https://github.com/sigp/lighthouse/issues/275
        let mut indices_to_delete = vec![];

        for included in included_deposits {
            for (i, for_inclusion) in self.deposits_for_inclusion.read().iter().enumerate() {
                if included == for_inclusion {
                    indices_to_delete.push(i);
                }
            }
        }

        let deposits_for_inclusion = &mut self.deposits_for_inclusion.write();
        for i in indices_to_delete {
            deposits_for_inclusion.remove(i);
        }
    }

    /// Accept some exit and queue it for inclusion in an appropriate block.
    pub fn receive_exit_for_inclusion(&self, exit: VoluntaryExit) {
        // TODO: exits are not checked for validity; check them.
        //
        // https://github.com/sigp/lighthouse/issues/276
        self.exits_for_inclusion.write().push(exit);
    }

    /// Return a vec of exits suitable for inclusion in some block.
    pub fn get_exits_for_block(&self) -> Vec<VoluntaryExit> {
        // TODO: exits are indiscriminately included; check them for validity.
        //
        // https://github.com/sigp/lighthouse/issues/275
        self.exits_for_inclusion.read().clone()
    }

    /// Takes a list of `Deposits` that were included in recent blocks and removes them from the
    /// inclusion queue.
    ///
    /// This ensures that `Deposits` are not included twice in successive blocks.
    pub fn set_exits_as_included(&self, included_exits: &[VoluntaryExit]) {
        // TODO: method does not take forks into account; consider this.
        let mut indices_to_delete = vec![];

        for included in included_exits {
            for (i, for_inclusion) in self.exits_for_inclusion.read().iter().enumerate() {
                if included == for_inclusion {
                    indices_to_delete.push(i);
                }
            }
        }

        let exits_for_inclusion = &mut self.exits_for_inclusion.write();
        for i in indices_to_delete {
            exits_for_inclusion.remove(i);
        }
    }

    /// Accept some transfer and queue it for inclusion in an appropriate block.
    pub fn receive_transfer_for_inclusion(&self, transfer: Transfer) {
        // TODO: transfers are not checked for validity; check them.
        //
        // https://github.com/sigp/lighthouse/issues/276
        self.transfers_for_inclusion.write().push(transfer);
    }

    /// Return a vec of transfers suitable for inclusion in some block.
    pub fn get_transfers_for_block(&self) -> Vec<Transfer> {
        // TODO: transfers are indiscriminately included; check them for validity.
        //
        // https://github.com/sigp/lighthouse/issues/275
        self.transfers_for_inclusion.read().clone()
    }

    /// Takes a list of `Deposits` that were included in recent blocks and removes them from the
    /// inclusion queue.
    ///
    /// This ensures that `Deposits` are not included twice in successive blocks.
    pub fn set_transfers_as_included(&self, included_transfers: &[Transfer]) {
        // TODO: method does not take forks into account; consider this.
        let mut indices_to_delete = vec![];

        for included in included_transfers {
            for (i, for_inclusion) in self.transfers_for_inclusion.read().iter().enumerate() {
                if included == for_inclusion {
                    indices_to_delete.push(i);
                }
            }
        }

        let transfers_for_inclusion = &mut self.transfers_for_inclusion.write();
        for i in indices_to_delete {
            transfers_for_inclusion.remove(i);
        }
    }

    /// Accept some proposer slashing and queue it for inclusion in an appropriate block.
    pub fn receive_proposer_slashing_for_inclusion(&self, proposer_slashing: ProposerSlashing) {
        // TODO: proposer_slashings are not checked for validity; check them.
        //
        // https://github.com/sigp/lighthouse/issues/276
        self.proposer_slashings_for_inclusion
            .write()
            .push(proposer_slashing);
    }

    /// Return a vec of proposer slashings suitable for inclusion in some block.
    pub fn get_proposer_slashings_for_block(&self) -> Vec<ProposerSlashing> {
        // TODO: proposer_slashings are indiscriminately included; check them for validity.
        //
        // https://github.com/sigp/lighthouse/issues/275
        self.proposer_slashings_for_inclusion.read().clone()
    }

    /// Takes a list of `ProposerSlashings` that were included in recent blocks and removes them
    /// from the inclusion queue.
    ///
    /// This ensures that `ProposerSlashings` are not included twice in successive blocks.
    pub fn set_proposer_slashings_as_included(
        &self,
        included_proposer_slashings: &[ProposerSlashing],
    ) {
        // TODO: method does not take forks into account; consider this.
        //
        // https://github.com/sigp/lighthouse/issues/275
        let mut indices_to_delete = vec![];

        for included in included_proposer_slashings {
            for (i, for_inclusion) in self
                .proposer_slashings_for_inclusion
                .read()
                .iter()
                .enumerate()
            {
                if included == for_inclusion {
                    indices_to_delete.push(i);
                }
            }
        }

        let proposer_slashings_for_inclusion = &mut self.proposer_slashings_for_inclusion.write();
        for i in indices_to_delete {
            proposer_slashings_for_inclusion.remove(i);
        }
    }

    /// Accept some attester slashing and queue it for inclusion in an appropriate block.
    pub fn receive_attester_slashing_for_inclusion(&self, attester_slashing: AttesterSlashing) {
        // TODO: attester_slashings are not checked for validity; check them.
        //
        // https://github.com/sigp/lighthouse/issues/276
        self.attester_slashings_for_inclusion
            .write()
            .push(attester_slashing);
    }

    /// Return a vec of attester slashings suitable for inclusion in some block.
    pub fn get_attester_slashings_for_block(&self) -> Vec<AttesterSlashing> {
        // TODO: attester_slashings are indiscriminately included; check them for validity.
        //
        // https://github.com/sigp/lighthouse/issues/275
        self.attester_slashings_for_inclusion.read().clone()
    }

    /// Takes a list of `AttesterSlashings` that were included in recent blocks and removes them
    /// from the inclusion queue.
    ///
    /// This ensures that `AttesterSlashings` are not included twice in successive blocks.
    pub fn set_attester_slashings_as_included(
        &self,
        included_attester_slashings: &[AttesterSlashing],
    ) {
        // TODO: method does not take forks into account; consider this.
        //
        // https://github.com/sigp/lighthouse/issues/275
        let mut indices_to_delete = vec![];

        for included in included_attester_slashings {
            for (i, for_inclusion) in self
                .attester_slashings_for_inclusion
                .read()
                .iter()
                .enumerate()
            {
                if included == for_inclusion {
                    indices_to_delete.push(i);
                }
            }
        }

        let attester_slashings_for_inclusion = &mut self.attester_slashings_for_inclusion.write();
        for i in indices_to_delete {
            attester_slashings_for_inclusion.remove(i);
        }
    }

    /// Accept some block and attempt to add it to block DAG.
    ///
    /// Will accept blocks from prior slots, however it will reject any block from a future slot.
    pub fn process_block(&self, block: BeaconBlock) -> Result<BlockProcessingOutcome, Error> {
        debug!("Processing block with slot {}...", block.slot);

        let block_root = block.into_header().canonical_root();

        let present_slot = self.present_slot();

        if block.slot > present_slot {
            return Ok(BlockProcessingOutcome::InvalidBlock(
                InvalidBlock::FutureSlot,
            ));
        }

        // Load the blocks parent block from the database, returning invalid if that block is not
        // found.
        let parent_block_root = block.previous_block_root;
        let parent_block = match self.block_store.get_deserialized(&parent_block_root)? {
            Some(previous_block_root) => previous_block_root,
            None => {
                return Ok(BlockProcessingOutcome::InvalidBlock(
                    InvalidBlock::ParentUnknown,
                ));
            }
        };

        // Load the parent blocks state from the database, returning an error if it is not found.
        // It is an error because if know the parent block we should also know the parent state.
        let parent_state_root = parent_block.state_root;
        let parent_state = self
            .state_store
            .get_deserialized(&parent_state_root)?
            .ok_or_else(|| Error::DBInconsistent(format!("Missing state {}", parent_state_root)))?;

        // TODO: check the block proposer signature BEFORE doing a state transition. This will
        // significantly lower exposure surface to DoS attacks.

        // Transition the parent state to the present slot.
        let mut state = parent_state;
        println!("parent process state: {:?}", state.latest_block_header);
        let previous_block_header = parent_block.into_header();
        for _ in state.slot.as_u64()..present_slot.as_u64() {
            if let Err(e) = per_slot_processing(&mut state, &previous_block_header, &self.spec) {
                return Ok(BlockProcessingOutcome::InvalidBlock(
                    InvalidBlock::SlotProcessingError(e),
                ));
            }
        }

        // Apply the received block to its parent state (which has been transitioned into this
        // slot).
        if let Err(e) = per_block_processing(&mut state, &block, &self.spec) {
            return Ok(BlockProcessingOutcome::InvalidBlock(
                InvalidBlock::PerBlockProcessingError(e),
            ));
        }

        println!("process state: {:?}", state.latest_block_header);

        let state_root = state.canonical_root();

        if block.state_root != state_root {
            return Ok(BlockProcessingOutcome::InvalidBlock(
                InvalidBlock::StateRootMismatch,
            ));
        }

        // Store the block and state.
        self.block_store.put(&block_root, &ssz_encode(&block)[..])?;
        self.state_store.put(&state_root, &ssz_encode(&state)[..])?;

        // Update the inclusion queues so they aren't re-submitted.
        self.set_deposits_as_included(&block.body.deposits[..]);
        self.set_transfers_as_included(&block.body.transfers[..]);
        self.set_exits_as_included(&block.body.voluntary_exits[..]);
        self.set_proposer_slashings_as_included(&block.body.proposer_slashings[..]);
        self.set_attester_slashings_as_included(&block.body.attester_slashings[..]);

        // run the fork_choice add_block logic
        self.fork_choice
            .write()
            .add_block(&block, &block_root, &self.spec)?;

        // If the parent block was the parent_block, automatically update the canonical head.
        //
        // TODO: this is a first-in-best-dressed scenario that is not ideal; fork_choice should be
        // run instead.
        if self.head().beacon_block_root == parent_block_root {
            self.update_canonical_head(block.clone(), block_root, state.clone(), state_root);
            // Update the local state variable.
            *self.state.write() = state;
        }

        Ok(BlockProcessingOutcome::ValidBlock(ValidBlock::Processed))
    }

    /// Produce a new block at the present slot.
    ///
    /// The produced block will not be inherently valid, it must be signed by a block producer.
    /// Block signing is out of the scope of this function and should be done by a separate program.
    pub fn produce_block(
        &self,
        randao_reveal: Signature,
    ) -> Result<(BeaconBlock, BeaconState), BlockProductionError> {
        debug!("Producing block at slot {}...", self.state.read().slot);

        let mut state = self.state.read().clone();

        trace!("Finding attestations for new block...");

        let attestations = self
            .attestation_aggregator
            .read()
            .get_attestations_for_state(&state, &self.spec);

        trace!(
            "Inserting {} attestation(s) into new block.",
            attestations.len()
        );

        let previous_block_root = *state
            .get_block_root(state.slot - 1, &self.spec)
            .map_err(|_| BlockProductionError::UnableToGetBlockRootFromState)?;

        let mut block = BeaconBlock {
            slot: state.slot,
            previous_block_root,
            state_root: Hash256::zero(), // Updated after the state is calculated.
            signature: self.spec.empty_signature.clone(), // To be completed by a validator.
            body: BeaconBlockBody {
                randao_reveal,
                eth1_data: Eth1Data {
                    // TODO: replace with real data
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                },
                proposer_slashings: self.get_proposer_slashings_for_block(),
                attester_slashings: self.get_attester_slashings_for_block(),
                attestations,
                deposits: self.get_deposits_for_block(),
                voluntary_exits: self.get_exits_for_block(),
                transfers: self.get_transfers_for_block(),
            },
        };

        trace!("BeaconChain::produce_block: updating state for new block.",);

        per_block_processing_without_verifying_block_signature(&mut state, &block, &self.spec)?;

        println!("produce state: {:?}", state.latest_block_header);

        let state_root = state.canonical_root();

        block.state_root = state_root;

        Ok((block, state))
    }

    // TODO: Left this as is, modify later
    pub fn fork_choice(&self) -> Result<(), Error> {
        let present_head = self.finalized_head().beacon_block_root;

        let new_head = self
            .fork_choice
            .write()
            .find_head(&present_head, &self.spec)?;

        if new_head != present_head {
            let block = self
                .block_store
                .get_deserialized(&new_head)?
                .ok_or_else(|| Error::MissingBeaconBlock(new_head))?;
            let block_root = block.canonical_root();

            let state = self
                .state_store
                .get_deserialized(&block.state_root)?
                .ok_or_else(|| Error::MissingBeaconState(block.state_root))?;
            let state_root = state.canonical_root();

            self.update_canonical_head(block, block_root, state, state_root);
        }

        Ok(())
    }

    /// Dumps the entire canonical chain, from the head to genesis to a vector for analysis.
    ///
    /// This could be a very expensive operation and should only be done in testing/analysis
    /// activities.
    pub fn chain_dump(&self) -> Result<Vec<CheckPoint>, Error> {
        let mut dump = vec![];

        let mut last_slot = CheckPoint {
            beacon_block: self.head().beacon_block.clone(),
            beacon_block_root: self.head().beacon_block_root,
            beacon_state: self.head().beacon_state.clone(),
            beacon_state_root: self.head().beacon_state_root,
        };

        dump.push(last_slot.clone());

        loop {
            let beacon_block_root = last_slot.beacon_block.previous_block_root;

            if beacon_block_root == self.spec.zero_hash {
                break; // Genesis has been reached.
            }

            let beacon_block = self
                .block_store
                .get_deserialized(&beacon_block_root)?
                .ok_or_else(|| {
                    Error::DBInconsistent(format!("Missing block {}", beacon_block_root))
                })?;
            let beacon_state_root = beacon_block.state_root;
            let beacon_state = self
                .state_store
                .get_deserialized(&beacon_state_root)?
                .ok_or_else(|| {
                    Error::DBInconsistent(format!("Missing state {}", beacon_state_root))
                })?;

            let slot = CheckPoint {
                beacon_block,
                beacon_block_root,
                beacon_state,
                beacon_state_root,
            };

            dump.push(slot.clone());
            last_slot = slot;
        }

        dump.reverse();

        Ok(dump)
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError(e.message)
    }
}

impl From<ForkChoiceError> for Error {
    fn from(e: ForkChoiceError) -> Error {
        Error::ForkChoiceError(e)
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}
