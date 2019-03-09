use self::epoch_cache::EpochCache;
use crate::test_utils::TestRandom;
use crate::{validator_registry::get_active_validator_indices, *};
use bls::verify_proof_of_possession;
use helpers::*;
use honey_badger_split::SplitExt;
use int_to_bytes::int_to_bytes32;
use log::{debug, error, trace};
use rand::RngCore;
use rayon::prelude::*;
use serde_derive::Serialize;
use ssz::{hash, Decodable, DecodeError, Encodable, SszStream, TreeHash};
use std::collections::HashMap;
use swap_or_not_shuffle::shuffle_list;

pub use builder::BeaconStateBuilder;

mod builder;
mod epoch_cache;
pub mod helpers;
mod tests;

pub type Committee = Vec<usize>;
pub type CrosslinkCommittees = Vec<(Committee, u64)>;
pub type Shard = u64;
pub type CommitteeIndex = u64;
pub type AttestationDuty = (Slot, Shard, CommitteeIndex);
pub type AttestationDutyMap = HashMap<u64, AttestationDuty>;
pub type ShardCommitteeIndexMap = HashMap<Shard, (usize, usize)>;

pub const CACHED_EPOCHS: usize = 3;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RelativeEpoch {
    Previous,
    Current,
    Next,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    EpochOutOfBounds,
    /// The supplied shard is unknown. It may be larger than the maximum shard count, or not in a
    /// committee for the given slot.
    SlotOutOfBounds,
    ShardOutOfBounds,
    UnableToShuffle,
    UnknownValidator,
    InvalidBitfield,
    InsufficientRandaoMixes,
    InsufficientValidators,
    InsufficientBlockRoots,
    InsufficientIndexRoots,
    InsufficientAttestations,
    InsufficientCommittees,
    EpochCacheUninitialized(RelativeEpoch),
}

macro_rules! safe_add_assign {
    ($a: expr, $b: expr) => {
        $a = $a.saturating_add($b);
    };
}
macro_rules! safe_sub_assign {
    ($a: expr, $b: expr) => {
        $a = $a.saturating_sub($b);
    };
}

#[derive(Debug, PartialEq, Clone, Default, Serialize)]
pub struct BeaconState {
    // Misc
    pub slot: Slot,
    pub genesis_time: u64,
    pub fork: Fork,

    // Validator registry
    pub validator_registry: Vec<Validator>,
    pub validator_balances: Vec<u64>,
    pub validator_registry_update_epoch: Epoch,

    // Randomness and committees
    pub latest_randao_mixes: Vec<Hash256>,
    pub previous_shuffling_start_shard: u64,
    pub current_shuffling_start_shard: u64,
    pub previous_shuffling_epoch: Epoch,
    pub current_shuffling_epoch: Epoch,
    pub previous_shuffling_seed: Hash256,
    pub current_shuffling_seed: Hash256,

    // Finality
    pub previous_justified_epoch: Epoch,
    pub justified_epoch: Epoch,
    pub justification_bitfield: u64,
    pub finalized_epoch: Epoch,

    // Recent state
    pub latest_crosslinks: Vec<Crosslink>,
    pub latest_block_roots: Vec<Hash256>,
    pub latest_active_index_roots: Vec<Hash256>,
    pub latest_slashed_balances: Vec<u64>,
    pub latest_attestations: Vec<PendingAttestation>,
    pub batched_block_roots: Vec<Hash256>,

    // Ethereum 1.0 chain data
    pub latest_eth1_data: Eth1Data,
    pub eth1_data_votes: Vec<Eth1DataVote>,
    pub deposit_index: u64,

    // Caching (not in the spec)
    pub cache_index_offset: usize,
    pub caches: Vec<EpochCache>,
}

impl BeaconState {
    /// Produce the first state of the Beacon Chain.
    pub fn genesis_without_validators(
        genesis_time: u64,
        latest_eth1_data: Eth1Data,
        spec: &ChainSpec,
    ) -> Result<BeaconState, Error> {
        debug!("Creating genesis state (without validator processing).");
        let initial_crosslink = Crosslink {
            epoch: spec.genesis_epoch,
            crosslink_data_root: spec.zero_hash,
        };

        Ok(BeaconState {
            /*
             * Misc
             */
            slot: spec.genesis_slot,
            genesis_time,
            fork: Fork {
                previous_version: spec.genesis_fork_version,
                current_version: spec.genesis_fork_version,
                epoch: spec.genesis_epoch,
            },

            /*
             * Validator registry
             */
            validator_registry: vec![], // Set later in the function.
            validator_balances: vec![], // Set later in the function.
            validator_registry_update_epoch: spec.genesis_epoch,

            /*
             * Randomness and committees
             */
            latest_randao_mixes: vec![spec.zero_hash; spec.latest_randao_mixes_length as usize],
            previous_shuffling_start_shard: spec.genesis_start_shard,
            current_shuffling_start_shard: spec.genesis_start_shard,
            previous_shuffling_epoch: spec.genesis_epoch,
            current_shuffling_epoch: spec.genesis_epoch,
            previous_shuffling_seed: spec.zero_hash,
            current_shuffling_seed: spec.zero_hash,

            /*
             * Finality
             */
            previous_justified_epoch: spec.genesis_epoch,
            justified_epoch: spec.genesis_epoch,
            justification_bitfield: 0,
            finalized_epoch: spec.genesis_epoch,

            /*
             * Recent state
             */
            latest_crosslinks: vec![initial_crosslink; spec.shard_count as usize],
            latest_block_roots: vec![spec.zero_hash; spec.latest_block_roots_length as usize],
            latest_active_index_roots: vec![
                spec.zero_hash;
                spec.latest_active_index_roots_length as usize
            ],
            latest_slashed_balances: vec![0; spec.latest_slashed_exit_length as usize],
            latest_attestations: vec![],
            batched_block_roots: vec![],

            /*
             * PoW receipt root
             */
            latest_eth1_data,
            eth1_data_votes: vec![],
            deposit_index: 0,

            /*
             * Caching (not in spec)
             */
            cache_index_offset: 0,
            caches: vec![EpochCache::empty(); CACHED_EPOCHS],
        })
    }

    /// Produce the first state of the Beacon Chain.
    pub fn genesis(
        genesis_time: u64,
        initial_validator_deposits: Vec<Deposit>,
        latest_eth1_data: Eth1Data,
        spec: &ChainSpec,
    ) -> Result<BeaconState, Error> {
        let mut genesis_state =
            BeaconState::genesis_without_validators(genesis_time, latest_eth1_data, spec)?;

        debug!("Processing genesis deposits...");

        let deposit_data = initial_validator_deposits
            .par_iter()
            .map(|deposit| &deposit.deposit_data)
            .collect();

        genesis_state.process_deposits(deposit_data, spec);

        trace!("Processed genesis deposits.");

        for validator_index in 0..genesis_state.validator_registry.len() {
            if genesis_state.get_effective_balance(validator_index, spec) >= spec.max_deposit_amount
            {
                genesis_state.activate_validator(validator_index, true, spec);
            }
        }

        genesis_state.deposit_index = initial_validator_deposits.len() as u64;

        let genesis_active_index_root = hash_tree_root(get_active_validator_indices(
            &genesis_state.validator_registry,
            spec.genesis_epoch,
        ));
        genesis_state.latest_active_index_roots =
            vec![genesis_active_index_root; spec.latest_active_index_roots_length];
        genesis_state.current_shuffling_seed =
            genesis_state.generate_seed(spec.genesis_epoch, spec)?;

        Ok(genesis_state)
    }

    /// Returns the `hash_tree_root` of the state.
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.hash_tree_root()[..])
    }

    /// Build an epoch cache, unless it is has already been built.
    pub fn build_epoch_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let cache_index = self.cache_index(relative_epoch);

        if self.caches[cache_index].initialized {
            Ok(())
        } else {
            self.force_build_epoch_cache(relative_epoch, spec)
        }
    }

    /// Always builds an epoch cache, even if it is already initialized.
    pub fn force_build_epoch_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let epoch = self.absolute_epoch(relative_epoch, spec);
        let cache_index = self.cache_index(relative_epoch);

        self.caches[cache_index] = EpochCache::initialized(&self, epoch, spec)?;

        Ok(())
    }

    /// Converts a `RelativeEpoch` into an `Epoch` with respect to the epoch of this state.
    fn absolute_epoch(&self, relative_epoch: RelativeEpoch, spec: &ChainSpec) -> Epoch {
        match relative_epoch {
            RelativeEpoch::Previous => self.previous_epoch(spec),
            RelativeEpoch::Current => self.current_epoch(spec),
            RelativeEpoch::Next => self.next_epoch(spec),
        }
    }

    /// Converts an `Epoch` into a `RelativeEpoch` with respect to the epoch of this state.
    ///
    /// Returns an error if the given `epoch` not "previous", "current" or "next" compared to the
    /// epoch of this tate.
    fn relative_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> Result<RelativeEpoch, Error> {
        match epoch {
            e if e == self.current_epoch(spec) => Ok(RelativeEpoch::Current),
            e if e == self.previous_epoch(spec) => Ok(RelativeEpoch::Previous),
            e if e == self.next_epoch(spec) => Ok(RelativeEpoch::Next),
            _ => Err(Error::EpochOutOfBounds),
        }
    }

    /// Advances the cache for this state into the next epoch.
    ///
    /// This should be used if the `slot` of this state is advanced beyond an epoch boundary.
    ///
    /// The `Next` cache becomes the `Current` and the `Current` cache becomes the `Previous`. The
    /// `Previous` cache is abandoned.
    ///
    /// Care should be taken to update the `Current` epoch in case a registry update is performed
    /// -- `Next` epoch is always _without_ a registry change. If you perform a registry update,
    /// you should rebuild the `Current` cache so it uses the new seed.
    pub fn advance_caches(&mut self) {
        self.drop_cache(RelativeEpoch::Previous);

        self.cache_index_offset += 1;
        self.cache_index_offset %= CACHED_EPOCHS;
    }

    /// Removes the specified cache and sets it to uninitialized.
    pub fn drop_cache(&mut self, relative_epoch: RelativeEpoch) {
        let previous_cache_index = self.cache_index(relative_epoch);
        self.caches[previous_cache_index] = EpochCache::empty();
    }

    /// Returns the index of `self.caches` for some `RelativeEpoch`.
    fn cache_index(&self, relative_epoch: RelativeEpoch) -> usize {
        let base_index = match relative_epoch {
            RelativeEpoch::Current => 1,
            RelativeEpoch::Previous => 0,
            RelativeEpoch::Next => 2,
        };

        (base_index + self.cache_index_offset) % CACHED_EPOCHS
    }

    /// Returns the cache for some `RelativeEpoch`. Returns an error if the cache has not been
    /// initialized.
    fn cache(&self, relative_epoch: RelativeEpoch) -> Result<&EpochCache, Error> {
        let cache = &self.caches[self.cache_index(relative_epoch)];

        if cache.initialized {
            Ok(cache)
        } else {
            Err(Error::EpochCacheUninitialized(relative_epoch))
        }
    }

    /// The epoch corresponding to `self.slot`.
    ///
    /// Spec v0.4.0
    pub fn current_epoch(&self, spec: &ChainSpec) -> Epoch {
        self.slot.epoch(spec.slots_per_epoch)
    }

    /// The epoch prior to `self.current_epoch()`.
    ///
    /// If the current epoch is the genesis epoch, the genesis_epoch is returned.
    ///
    /// Spec v0.4.0
    pub fn previous_epoch(&self, spec: &ChainSpec) -> Epoch {
        let current_epoch = self.current_epoch(&spec);
        std::cmp::max(current_epoch - 1, spec.genesis_epoch)
    }

    /// The epoch following `self.current_epoch()`.
    ///
    /// Spec v0.4.0
    pub fn next_epoch(&self, spec: &ChainSpec) -> Epoch {
        self.current_epoch(spec).saturating_add(1_u64)
    }

    /// The first slot of the epoch corresponding to `self.slot`.
    ///
    /// Spec v0.4.0
    pub fn current_epoch_start_slot(&self, spec: &ChainSpec) -> Slot {
        self.current_epoch(spec).start_slot(spec.slots_per_epoch)
    }

    /// The first slot of the epoch preceding the one corresponding to `self.slot`.
    ///
    /// Spec v0.4.0
    pub fn previous_epoch_start_slot(&self, spec: &ChainSpec) -> Slot {
        self.previous_epoch(spec).start_slot(spec.slots_per_epoch)
    }

    /// Return the number of committees in the previous epoch.
    ///
    /// Spec v0.4.0
    fn get_previous_epoch_committee_count(&self, spec: &ChainSpec) -> u64 {
        let previous_active_validators =
            get_active_validator_indices(&self.validator_registry, self.previous_shuffling_epoch);
        spec.get_epoch_committee_count(previous_active_validators.len())
    }

    /// Return the number of committees in the current epoch.
    ///
    /// Spec v0.4.0
    pub fn get_current_epoch_committee_count(&self, spec: &ChainSpec) -> u64 {
        let current_active_validators =
            get_active_validator_indices(&self.validator_registry, self.current_shuffling_epoch);
        spec.get_epoch_committee_count(current_active_validators.len())
    }

    /// Return the number of committees in the next epoch.
    ///
    /// Spec v0.4.0
    pub fn get_next_epoch_committee_count(&self, spec: &ChainSpec) -> u64 {
        let next_active_validators =
            get_active_validator_indices(&self.validator_registry, self.next_epoch(spec));
        spec.get_epoch_committee_count(next_active_validators.len())
    }

    /// Returns the crosslink committees for some slot.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.4.0
    pub fn get_crosslink_committees_at_slot(
        &self,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Result<&CrosslinkCommittees, Error> {
        let epoch = slot.epoch(spec.slots_per_epoch);
        let relative_epoch = self.relative_epoch(epoch, spec)?;
        let cache = self.cache(relative_epoch)?;

        let slot_offset = slot - epoch.start_slot(spec.slots_per_epoch);

        Ok(&cache.committees[slot_offset.as_usize()])
    }

    /// Return the block root at a recent `slot`.
    ///
    /// Spec v0.4.0
    pub fn get_block_root(&self, slot: Slot, spec: &ChainSpec) -> Option<&Hash256> {
        if (self.slot <= slot + spec.latest_block_roots_length as u64) && (slot < self.slot) {
            self.latest_block_roots
                .get(slot.as_usize() % spec.latest_block_roots_length)
        } else {
            None
        }
    }

    /// Return the randao mix at a recent ``epoch``.
    ///
    /// Spec v0.4.0
    pub fn get_randao_mix(&self, epoch: Epoch, spec: &ChainSpec) -> Option<&Hash256> {
        let current_epoch = self.current_epoch(spec);

        if (current_epoch - (spec.latest_randao_mixes_length as u64) < epoch)
            & (epoch <= current_epoch)
        {
            self.latest_randao_mixes
                .get(epoch.as_usize() % spec.latest_randao_mixes_length)
        } else {
            None
        }
    }

    /// Return the index root at a recent `epoch`.
    ///
    /// Spec v0.4.0
    pub fn get_active_index_root(&self, epoch: Epoch, spec: &ChainSpec) -> Option<Hash256> {
        let current_epoch = self.current_epoch(spec);

        if (current_epoch - spec.latest_active_index_roots_length as u64
            + spec.activation_exit_delay
            < epoch)
            & (epoch <= current_epoch + spec.activation_exit_delay)
        {
            Some(
                self.latest_active_index_roots
                    [epoch.as_usize() % spec.latest_active_index_roots_length],
            )
        } else {
            None
        }
    }

    /// Generate a seed for the given `epoch`.
    ///
    /// Spec v0.4.0
    pub fn generate_seed(&self, epoch: Epoch, spec: &ChainSpec) -> Result<Hash256, Error> {
        let mut input = self
            .get_randao_mix(epoch - spec.min_seed_lookahead, spec)
            .ok_or_else(|| Error::InsufficientRandaoMixes)?
            .as_bytes()
            .to_vec();

        input.append(
            &mut self
                .get_active_index_root(epoch, spec)
                .ok_or_else(|| Error::InsufficientIndexRoots)?
                .as_bytes()
                .to_vec(),
        );

        input.append(&mut int_to_bytes32(epoch.as_u64()));

        Ok(Hash256::from_slice(&hash(&input[..])[..]))
    }

    /// Returns the beacon proposer index for the `slot`.
    ///
    /// If the state does not contain an index for a beacon proposer at the requested `slot`, then `None` is returned.
    ///
    /// Spec v0.4.0
    pub fn get_beacon_proposer_index(&self, slot: Slot, spec: &ChainSpec) -> Result<usize, Error> {
        let committees = self.get_crosslink_committees_at_slot(slot, spec)?;
        trace!(
            "get_beacon_proposer_index: slot: {}, committees_count: {}",
            slot,
            committees.len()
        );
        committees
            .first()
            .ok_or(Error::InsufficientValidators)
            .and_then(|(first_committee, _)| {
                let index = slot
                    .as_usize()
                    .checked_rem(first_committee.len())
                    .ok_or(Error::InsufficientValidators)?;
                Ok(first_committee[index])
            })
    }

    /// Returns the list of validator indices which participiated in the attestation.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.4.0
    pub fn get_attestation_participants(
        &self,
        attestation_data: &AttestationData,
        bitfield: &Bitfield,
        spec: &ChainSpec,
    ) -> Result<Vec<usize>, Error> {
        let epoch = attestation_data.slot.epoch(spec.slots_per_epoch);
        let relative_epoch = self.relative_epoch(epoch, spec)?;
        let cache = self.cache(relative_epoch)?;

        let (committee_slot_index, committee_index) = cache
            .shard_committee_index_map
            .get(&attestation_data.shard)
            .ok_or_else(|| Error::ShardOutOfBounds)?;
        let (committee, shard) = &cache.committees[*committee_slot_index][*committee_index];

        assert_eq!(*shard, attestation_data.shard, "Bad epoch cache build.");

        if !verify_bitfield_length(&bitfield, committee.len()) {
            return Err(Error::InvalidBitfield);
        }

        let mut participants = vec![];
        for (i, validator_index) in committee.iter().enumerate() {
            if bitfield.get(i).unwrap() {
                participants.push(*validator_index);
            }
        }

        Ok(participants)
    }

    /// Return the effective balance (also known as "balance at stake") for a validator with the given ``index``.
    ///
    /// Spec v0.4.0
    pub fn get_effective_balance(&self, validator_index: usize, spec: &ChainSpec) -> u64 {
        std::cmp::min(
            self.validator_balances[validator_index],
            spec.max_deposit_amount,
        )
    }

    /// Return the combined effective balance of an array of validators.
    ///
    /// Spec v0.4.0
    pub fn get_total_balance(&self, validator_indices: &[usize], spec: &ChainSpec) -> u64 {
        validator_indices
            .iter()
            .fold(0, |acc, i| acc + self.get_effective_balance(*i, spec))
    }

    ///  Return the epoch at which an activation or exit triggered in ``epoch`` takes effect.
    ///
    ///  Spec v0.4.0
    pub fn get_delayed_activation_exit_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> Epoch {
        epoch + 1 + spec.activation_exit_delay
    }

    /// Process multiple deposits in sequence.
    ///
    /// Builds a hashmap of validator pubkeys to validator index and passes it to each successive
    /// call to `process_deposit(..)`. This requires much less computation than successive calls to
    /// `process_deposits(..)` without the hashmap.
    ///
    /// Spec v0.4.0
    pub fn process_deposits(
        &mut self,
        deposits: Vec<&DepositData>,
        spec: &ChainSpec,
    ) -> Vec<usize> {
        let mut added_indices = vec![];
        let mut pubkey_map: HashMap<PublicKey, usize> = HashMap::new();

        for (i, validator) in self.validator_registry.iter().enumerate() {
            pubkey_map.insert(validator.pubkey.clone(), i);
        }

        for deposit_data in deposits {
            let result = self.process_deposit(
                deposit_data.deposit_input.pubkey.clone(),
                deposit_data.amount,
                deposit_data.deposit_input.proof_of_possession.clone(),
                deposit_data.deposit_input.withdrawal_credentials,
                Some(&pubkey_map),
                spec,
            );
            if let Ok(index) = result {
                added_indices.push(index);
            }
        }
        added_indices
    }

    /// Process a validator deposit, returning the validator index if the deposit is valid.
    ///
    /// Optionally accepts a hashmap of all validator pubkeys to their validator index. Without
    /// this hashmap, each call to `process_deposits` requires an iteration though
    /// `self.validator_registry`. This becomes highly inefficient at scale.
    ///
    /// Spec v0.4.0
    pub fn process_deposit(
        &mut self,
        pubkey: PublicKey,
        amount: u64,
        proof_of_possession: Signature,
        withdrawal_credentials: Hash256,
        pubkey_map: Option<&HashMap<PublicKey, usize>>,
        spec: &ChainSpec,
    ) -> Result<usize, ()> {
        // TODO: update proof of possession to function written above (
        // requires bls::create_proof_of_possession to be updated
        //
        // https://github.com/sigp/lighthouse/issues/239
        if !verify_proof_of_possession(&proof_of_possession, &pubkey) {
            return Err(());
        }

        let validator_index = if let Some(pubkey_map) = pubkey_map {
            pubkey_map.get(&pubkey).and_then(|i| Some(*i))
        } else {
            self.validator_registry
                .iter()
                .position(|v| v.pubkey == pubkey)
        };

        if let Some(index) = validator_index {
            if self.validator_registry[index].withdrawal_credentials == withdrawal_credentials {
                safe_add_assign!(self.validator_balances[index], amount);
                Ok(index)
            } else {
                Err(())
            }
        } else {
            let validator = Validator {
                pubkey,
                withdrawal_credentials,
                activation_epoch: spec.far_future_epoch,
                exit_epoch: spec.far_future_epoch,
                withdrawable_epoch: spec.far_future_epoch,
                initiated_exit: false,
                slashed: false,
            };
            self.validator_registry.push(validator);
            self.validator_balances.push(amount);
            Ok(self.validator_registry.len() - 1)
        }
    }

    /// Activate the validator of the given ``index``.
    ///
    /// Spec v0.4.0
    pub fn activate_validator(
        &mut self,
        validator_index: usize,
        is_genesis: bool,
        spec: &ChainSpec,
    ) {
        let current_epoch = self.current_epoch(spec);

        self.validator_registry[validator_index].activation_epoch = if is_genesis {
            spec.genesis_epoch
        } else {
            self.get_delayed_activation_exit_epoch(current_epoch, spec)
        }
    }

    /// Initiate an exit for the validator of the given `index`.
    ///
    /// Spec v0.4.0
    pub fn initiate_validator_exit(&mut self, validator_index: usize) {
        self.validator_registry[validator_index].initiated_exit = true;
    }

    /// Exit the validator of the given `index`.
    ///
    /// Spec v0.4.0
    fn exit_validator(&mut self, validator_index: usize, spec: &ChainSpec) {
        let current_epoch = self.current_epoch(spec);
        let delayed_epoch = self.get_delayed_activation_exit_epoch(current_epoch, spec);

        if self.validator_registry[validator_index].exit_epoch <= delayed_epoch {
            return;
        }

        self.validator_registry[validator_index].exit_epoch = delayed_epoch;
    }

    /// Slash the validator with index ``index``.
    ///
    /// Spec v0.4.0
    pub fn slash_validator(
        &mut self,
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let current_epoch = self.current_epoch(spec);

        let validator = &self
            .validator_registry
            .get(validator_index)
            .ok_or_else(|| Error::UnknownValidator)?;

        if self.slot
            >= validator
                .withdrawable_epoch
                .start_slot(spec.slots_per_epoch)
        {
            return Err(Error::SlotOutOfBounds);
        }

        self.exit_validator(validator_index, spec);

        self.latest_slashed_balances[current_epoch.as_usize() % spec.latest_slashed_exit_length] +=
            self.get_effective_balance(validator_index, spec);

        let whistleblower_index = self.get_beacon_proposer_index(self.slot, spec)?;
        let whistleblower_reward = self.get_effective_balance(validator_index, spec);
        safe_add_assign!(
            self.validator_balances[whistleblower_index as usize],
            whistleblower_reward
        );
        safe_sub_assign!(
            self.validator_balances[validator_index],
            whistleblower_reward
        );
        self.validator_registry[validator_index].slashed = true;
        self.validator_registry[validator_index].withdrawable_epoch =
            current_epoch + Epoch::from(spec.latest_slashed_exit_length);

        debug!(
            "Whistleblower {} penalized validator {}.",
            whistleblower_index, validator_index
        );

        Ok(())
    }

    /// Initiate an exit for the validator of the given `index`.
    ///
    /// Spec v0.4.0
    pub fn prepare_validator_for_withdrawal(&mut self, validator_index: usize, spec: &ChainSpec) {
        //TODO: we're not ANDing here, we're setting. Potentially wrong.
        self.validator_registry[validator_index].withdrawable_epoch =
            self.current_epoch(spec) + spec.min_validator_withdrawability_delay;
    }

    /// Returns the crosslink committees for some slot.
    ///
    /// Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.4.0
    pub(crate) fn get_shuffling_for_slot(
        &self,
        slot: Slot,
        registry_change: bool,

        spec: &ChainSpec,
    ) -> Result<Vec<Vec<usize>>, Error> {
        let (_committees_per_epoch, seed, shuffling_epoch, _shuffling_start_shard) =
            self.get_committee_params_at_slot(slot, registry_change, spec)?;

        self.get_shuffling(seed, shuffling_epoch, spec)
    }

    /// Shuffle ``validators`` into crosslink committees seeded by ``seed`` and ``epoch``.
    ///
    /// Return a list of ``committees_per_epoch`` committees where each
    /// committee is itself a list of validator indices.
    ///
    /// Spec v0.4.0
    pub(crate) fn get_shuffling(
        &self,
        seed: Hash256,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<Vec<Vec<usize>>, Error> {
        let active_validator_indices =
            get_active_validator_indices(&self.validator_registry, epoch);

        if active_validator_indices.is_empty() {
            error!("get_shuffling: no validators.");
            return Err(Error::InsufficientValidators);
        }

        debug!("Shuffling {} validators...", active_validator_indices.len());

        let committees_per_epoch = spec.get_epoch_committee_count(active_validator_indices.len());

        trace!(
            "get_shuffling: active_validator_indices.len() == {}, committees_per_epoch: {}",
            active_validator_indices.len(),
            committees_per_epoch
        );

        let active_validator_indices: Vec<usize> = active_validator_indices.to_vec();

        let shuffled_active_validator_indices = shuffle_list(
            active_validator_indices,
            spec.shuffle_round_count,
            &seed[..],
            true,
        )
        .ok_or_else(|| Error::UnableToShuffle)?;

        Ok(shuffled_active_validator_indices
            .honey_badger_split(committees_per_epoch as usize)
            .map(|slice: &[usize]| slice.to_vec())
            .collect())
    }

    /// Returns the following params for the given slot:
    ///
    /// - epoch committee count
    /// - epoch seed
    /// - calculation epoch
    /// - start shard
    ///
    /// In the spec, this functionality is included in the `get_crosslink_committees_at_slot(..)`
    /// function. It is separated here to allow the division of shuffling and committee building,
    /// as is required for efficient operations.
    ///
    /// Spec v0.4.0
    pub(crate) fn get_committee_params_at_slot(
        &self,
        slot: Slot,
        registry_change: bool,
        spec: &ChainSpec,
    ) -> Result<(u64, Hash256, Epoch, u64), Error> {
        let epoch = slot.epoch(spec.slots_per_epoch);
        let current_epoch = self.current_epoch(spec);
        let previous_epoch = self.previous_epoch(spec);
        let next_epoch = self.next_epoch(spec);

        if epoch == current_epoch {
            Ok((
                self.get_current_epoch_committee_count(spec),
                self.current_shuffling_seed,
                self.current_shuffling_epoch,
                self.current_shuffling_start_shard,
            ))
        } else if epoch == previous_epoch {
            Ok((
                self.get_previous_epoch_committee_count(spec),
                self.previous_shuffling_seed,
                self.previous_shuffling_epoch,
                self.previous_shuffling_start_shard,
            ))
        } else if epoch == next_epoch {
            let current_committees_per_epoch = self.get_current_epoch_committee_count(spec);
            let epochs_since_last_registry_update =
                current_epoch - self.validator_registry_update_epoch;
            let (seed, shuffling_start_shard) = if registry_change {
                let next_seed = self.generate_seed(next_epoch, spec)?;
                (
                    next_seed,
                    (self.current_shuffling_start_shard + current_committees_per_epoch)
                        % spec.shard_count,
                )
            } else if (epochs_since_last_registry_update > 1)
                & epochs_since_last_registry_update.is_power_of_two()
            {
                let next_seed = self.generate_seed(next_epoch, spec)?;
                (next_seed, self.current_shuffling_start_shard)
            } else {
                (
                    self.current_shuffling_seed,
                    self.current_shuffling_start_shard,
                )
            };
            Ok((
                self.get_next_epoch_committee_count(spec),
                seed,
                next_epoch,
                shuffling_start_shard,
            ))
        } else {
            Err(Error::EpochOutOfBounds)
        }
    }

    /// Return the list of ``(committee, shard)`` tuples for the ``slot``.
    ///
    /// Note: There are two possible shufflings for crosslink committees for a
    /// `slot` in the next epoch: with and without a `registry_change`
    ///
    /// Note: does not utilize the cache, `get_crosslink_committees_at_slot` is an equivalent
    /// function which uses the cache.
    ///
    /// Spec v0.4.0
    pub(crate) fn calculate_crosslink_committees_at_slot(
        &self,
        slot: Slot,
        registry_change: bool,
        shuffling: Vec<Vec<usize>>,
        spec: &ChainSpec,
    ) -> Result<Vec<(Vec<usize>, u64)>, Error> {
        let (committees_per_epoch, _seed, _shuffling_epoch, shuffling_start_shard) =
            self.get_committee_params_at_slot(slot, registry_change, spec)?;

        let offset = slot.as_u64() % spec.slots_per_epoch;
        let committees_per_slot = committees_per_epoch / spec.slots_per_epoch;
        let slot_start_shard =
            (shuffling_start_shard + committees_per_slot * offset) % spec.shard_count;

        let mut crosslinks_at_slot = vec![];
        for i in 0..committees_per_slot {
            let tuple = (
                shuffling[(committees_per_slot * offset + i) as usize].clone(),
                (slot_start_shard + i) % spec.shard_count,
            );
            crosslinks_at_slot.push(tuple)
        }
        Ok(crosslinks_at_slot)
    }

    /// Returns the `slot`, `shard` and `committee_index` for which a validator must produce an
    /// attestation.
    ///
    /// Only reads the current epoch.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.4.0
    pub fn attestation_slot_and_shard_for_validator(
        &self,
        validator_index: usize,
        _spec: &ChainSpec,
    ) -> Result<Option<(Slot, u64, u64)>, Error> {
        let cache = self.cache(RelativeEpoch::Current)?;

        Ok(cache
            .attestation_duty_map
            .get(&(validator_index as u64))
            .and_then(|tuple| Some(*tuple)))
    }

    /// Process the slashings.
    ///
    /// Spec v0.4.0
    pub fn process_slashings(&mut self, spec: &ChainSpec) {
        let current_epoch = self.current_epoch(spec);
        let active_validator_indices =
            get_active_validator_indices(&self.validator_registry, current_epoch);
        let total_balance = self.get_total_balance(&active_validator_indices[..], spec);

        for (index, validator) in self.validator_registry.iter().enumerate() {
            if validator.slashed
                && (current_epoch
                    == validator.withdrawable_epoch
                        - Epoch::from(spec.latest_slashed_exit_length / 2))
            {
                let epoch_index: usize = current_epoch.as_usize() % spec.latest_slashed_exit_length;

                let total_at_start = self.latest_slashed_balances
                    [(epoch_index + 1) % spec.latest_slashed_exit_length];
                let total_at_end = self.latest_slashed_balances[epoch_index];
                let total_penalities = total_at_end.saturating_sub(total_at_start);
                let penalty = std::cmp::max(
                    self.get_effective_balance(index, spec)
                        * std::cmp::min(total_penalities * 3, total_balance)
                        / total_balance,
                    self.get_effective_balance(index, spec) / spec.min_penalty_quotient,
                );

                safe_sub_assign!(self.validator_balances[index], penalty);
            }
        }
    }

    /// Process the exit queue.
    ///
    /// Spec v0.4.0
    pub fn process_exit_queue(&mut self, spec: &ChainSpec) {
        let current_epoch = self.current_epoch(spec);

        let eligible = |index: usize| {
            let validator = &self.validator_registry[index];

            if validator.withdrawable_epoch != spec.far_future_epoch {
                false
            } else {
                current_epoch >= validator.exit_epoch + spec.min_validator_withdrawability_delay
            }
        };

        let mut eligable_indices: Vec<usize> = (0..self.validator_registry.len())
            .filter(|i| eligible(*i))
            .collect();
        eligable_indices.sort_by_key(|i| self.validator_registry[*i].exit_epoch);

        for (withdrawn_so_far, index) in eligable_indices.iter().enumerate() {
            if withdrawn_so_far as u64 >= spec.max_exit_dequeues_per_epoch {
                break;
            }
            self.prepare_validator_for_withdrawal(*index, spec);
        }
    }

    /// Update validator registry, activating/exiting validators if possible.
    ///
    /// Spec v0.4.0
    pub fn update_validator_registry(&mut self, spec: &ChainSpec) {
        let current_epoch = self.current_epoch(spec);
        let active_validator_indices =
            get_active_validator_indices(&self.validator_registry, current_epoch);
        let total_balance = self.get_total_balance(&active_validator_indices[..], spec);

        let max_balance_churn = std::cmp::max(
            spec.max_deposit_amount,
            total_balance / (2 * spec.max_balance_churn_quotient),
        );

        let mut balance_churn = 0;
        for index in 0..self.validator_registry.len() {
            let validator = &self.validator_registry[index];

            if (validator.activation_epoch == spec.far_future_epoch)
                & (self.validator_balances[index] == spec.max_deposit_amount)
            {
                balance_churn += self.get_effective_balance(index, spec);
                if balance_churn > max_balance_churn {
                    break;
                }
                self.activate_validator(index, false, spec);
            }
        }

        let mut balance_churn = 0;
        for index in 0..self.validator_registry.len() {
            let validator = &self.validator_registry[index];

            if (validator.exit_epoch == spec.far_future_epoch) & (validator.initiated_exit) {
                balance_churn += self.get_effective_balance(index, spec);
                if balance_churn > max_balance_churn {
                    break;
                }

                self.exit_validator(index, spec);
            }
        }

        self.validator_registry_update_epoch = current_epoch;
    }

    /// Confirm validator owns PublicKey
    ///
    /// Spec v0.4.0
    pub fn validate_proof_of_possession(
        &self,
        pubkey: PublicKey,
        proof_of_possession: Signature,
        withdrawal_credentials: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        let proof_of_possession_data = DepositInput {
            pubkey: pubkey.clone(),
            withdrawal_credentials,
            proof_of_possession: Signature::empty_signature(),
        };

        proof_of_possession.verify(
            &proof_of_possession_data.hash_tree_root(),
            spec.get_domain(
                self.slot.epoch(spec.slots_per_epoch),
                Domain::Deposit,
                &self.fork,
            ),
            &pubkey,
        )
    }

    /// Iterate through the validator registry and eject active validators with balance below
    /// ``EJECTION_BALANCE``.
    ///
    /// Spec v0.4.0
    pub fn process_ejections(&mut self, spec: &ChainSpec) {
        for validator_index in
            get_active_validator_indices(&self.validator_registry, self.current_epoch(spec))
        {
            if self.validator_balances[validator_index] < spec.ejection_balance {
                self.exit_validator(validator_index, spec)
            }
        }
    }

    /// Returns the penality that should be applied to some validator for inactivity.
    ///
    /// Note: this is defined "inline" in the spec, not as a helper function.
    ///
    /// Spec v0.4.0
    pub fn inactivity_penalty(
        &self,
        validator_index: usize,
        epochs_since_finality: Epoch,
        base_reward_quotient: u64,
        spec: &ChainSpec,
    ) -> u64 {
        let effective_balance = self.get_effective_balance(validator_index, spec);
        self.base_reward(validator_index, base_reward_quotient, spec)
            + effective_balance * epochs_since_finality.as_u64()
                / spec.inactivity_penalty_quotient
                / 2
    }

    /// Returns the base reward for some validator.
    ///
    /// Note: In the spec this is defined "inline", not as a helper function.
    ///
    /// Spec v0.4.0
    pub fn base_reward(
        &self,
        validator_index: usize,
        base_reward_quotient: u64,
        spec: &ChainSpec,
    ) -> u64 {
        self.get_effective_balance(validator_index, spec) / base_reward_quotient / 5
    }

    /// Returns the union of all participants in the provided attestations
    ///
    /// Spec v0.4.0
    pub fn get_attestation_participants_union(
        &self,
        attestations: &[&PendingAttestation],
        spec: &ChainSpec,
    ) -> Result<Vec<usize>, Error> {
        let mut all_participants = attestations
            .iter()
            .try_fold::<_, _, Result<Vec<usize>, Error>>(vec![], |mut acc, a| {
                acc.append(&mut self.get_attestation_participants(
                    &a.data,
                    &a.aggregation_bitfield,
                    spec,
                )?);
                Ok(acc)
            })?;
        all_participants.sort_unstable();
        all_participants.dedup();
        Ok(all_participants)
    }
}

fn hash_tree_root<T: TreeHash>(input: Vec<T>) -> Hash256 {
    Hash256::from_slice(&input.hash_tree_root()[..])
}

impl Encodable for BeaconState {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.genesis_time);
        s.append(&self.fork);
        s.append(&self.validator_registry);
        s.append(&self.validator_balances);
        s.append(&self.validator_registry_update_epoch);
        s.append(&self.latest_randao_mixes);
        s.append(&self.previous_shuffling_start_shard);
        s.append(&self.current_shuffling_start_shard);
        s.append(&self.previous_shuffling_epoch);
        s.append(&self.current_shuffling_epoch);
        s.append(&self.previous_shuffling_seed);
        s.append(&self.current_shuffling_seed);
        s.append(&self.previous_justified_epoch);
        s.append(&self.justified_epoch);
        s.append(&self.justification_bitfield);
        s.append(&self.finalized_epoch);
        s.append(&self.latest_crosslinks);
        s.append(&self.latest_block_roots);
        s.append(&self.latest_active_index_roots);
        s.append(&self.latest_slashed_balances);
        s.append(&self.latest_attestations);
        s.append(&self.batched_block_roots);
        s.append(&self.latest_eth1_data);
        s.append(&self.eth1_data_votes);
        s.append(&self.deposit_index);
    }
}

impl Decodable for BeaconState {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = <_>::ssz_decode(bytes, i)?;
        let (genesis_time, i) = <_>::ssz_decode(bytes, i)?;
        let (fork, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_balances, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_registry_update_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_randao_mixes, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_shuffling_start_shard, i) = <_>::ssz_decode(bytes, i)?;
        let (current_shuffling_start_shard, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_shuffling_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (current_shuffling_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_shuffling_seed, i) = <_>::ssz_decode(bytes, i)?;
        let (current_shuffling_seed, i) = <_>::ssz_decode(bytes, i)?;
        let (previous_justified_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (justified_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (justification_bitfield, i) = <_>::ssz_decode(bytes, i)?;
        let (finalized_epoch, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_crosslinks, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_block_roots, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_active_index_roots, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_slashed_balances, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_attestations, i) = <_>::ssz_decode(bytes, i)?;
        let (batched_block_roots, i) = <_>::ssz_decode(bytes, i)?;
        let (latest_eth1_data, i) = <_>::ssz_decode(bytes, i)?;
        let (eth1_data_votes, i) = <_>::ssz_decode(bytes, i)?;
        let (deposit_index, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                genesis_time,
                fork,
                validator_registry,
                validator_balances,
                validator_registry_update_epoch,
                latest_randao_mixes,
                previous_shuffling_start_shard,
                current_shuffling_start_shard,
                previous_shuffling_epoch,
                current_shuffling_epoch,
                previous_shuffling_seed,
                current_shuffling_seed,
                previous_justified_epoch,
                justified_epoch,
                justification_bitfield,
                finalized_epoch,
                latest_crosslinks,
                latest_block_roots,
                latest_active_index_roots,
                latest_slashed_balances,
                latest_attestations,
                batched_block_roots,
                latest_eth1_data,
                eth1_data_votes,
                deposit_index,
                cache_index_offset: 0,
                caches: vec![EpochCache::empty(); CACHED_EPOCHS],
            },
            i,
        ))
    }
}

impl TreeHash for BeaconState {
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        result.append(&mut self.slot.hash_tree_root());
        result.append(&mut self.genesis_time.hash_tree_root());
        result.append(&mut self.fork.hash_tree_root());
        result.append(&mut self.validator_registry.hash_tree_root());
        result.append(&mut self.validator_balances.hash_tree_root());
        result.append(&mut self.validator_registry_update_epoch.hash_tree_root());
        result.append(&mut self.latest_randao_mixes.hash_tree_root());
        result.append(&mut self.previous_shuffling_start_shard.hash_tree_root());
        result.append(&mut self.current_shuffling_start_shard.hash_tree_root());
        result.append(&mut self.previous_shuffling_epoch.hash_tree_root());
        result.append(&mut self.current_shuffling_epoch.hash_tree_root());
        result.append(&mut self.previous_shuffling_seed.hash_tree_root());
        result.append(&mut self.current_shuffling_seed.hash_tree_root());
        result.append(&mut self.previous_justified_epoch.hash_tree_root());
        result.append(&mut self.justified_epoch.hash_tree_root());
        result.append(&mut self.justification_bitfield.hash_tree_root());
        result.append(&mut self.finalized_epoch.hash_tree_root());
        result.append(&mut self.latest_crosslinks.hash_tree_root());
        result.append(&mut self.latest_block_roots.hash_tree_root());
        result.append(&mut self.latest_active_index_roots.hash_tree_root());
        result.append(&mut self.latest_slashed_balances.hash_tree_root());
        result.append(&mut self.latest_attestations.hash_tree_root());
        result.append(&mut self.batched_block_roots.hash_tree_root());
        result.append(&mut self.latest_eth1_data.hash_tree_root());
        result.append(&mut self.eth1_data_votes.hash_tree_root());
        result.append(&mut self.deposit_index.hash_tree_root());
        hash(&result)
    }
}

impl<T: RngCore> TestRandom<T> for BeaconState {
    fn random_for_test(rng: &mut T) -> Self {
        Self {
            slot: <_>::random_for_test(rng),
            genesis_time: <_>::random_for_test(rng),
            fork: <_>::random_for_test(rng),
            validator_registry: <_>::random_for_test(rng),
            validator_balances: <_>::random_for_test(rng),
            validator_registry_update_epoch: <_>::random_for_test(rng),
            latest_randao_mixes: <_>::random_for_test(rng),
            previous_shuffling_start_shard: <_>::random_for_test(rng),
            current_shuffling_start_shard: <_>::random_for_test(rng),
            previous_shuffling_epoch: <_>::random_for_test(rng),
            current_shuffling_epoch: <_>::random_for_test(rng),
            previous_shuffling_seed: <_>::random_for_test(rng),
            current_shuffling_seed: <_>::random_for_test(rng),
            previous_justified_epoch: <_>::random_for_test(rng),
            justified_epoch: <_>::random_for_test(rng),
            justification_bitfield: <_>::random_for_test(rng),
            finalized_epoch: <_>::random_for_test(rng),
            latest_crosslinks: <_>::random_for_test(rng),
            latest_block_roots: <_>::random_for_test(rng),
            latest_active_index_roots: <_>::random_for_test(rng),
            latest_slashed_balances: <_>::random_for_test(rng),
            latest_attestations: <_>::random_for_test(rng),
            batched_block_roots: <_>::random_for_test(rng),
            latest_eth1_data: <_>::random_for_test(rng),
            eth1_data_votes: <_>::random_for_test(rng),
            deposit_index: <_>::random_for_test(rng),
            cache_index_offset: 0,
            caches: vec![EpochCache::empty(); CACHED_EPOCHS],
        }
    }
}
