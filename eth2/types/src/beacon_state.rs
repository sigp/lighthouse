use self::epoch_cache::{EpochCache, Error as EpochCacheError};
use crate::test_utils::TestRandom;
use crate::*;
use int_to_bytes::int_to_bytes32;
use pubkey_cache::PubkeyCache;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz::{hash, ssz_encode, TreeHash};
use ssz_derive::{Decode, Encode, TreeHash};
use test_random_derive::TestRandom;

mod epoch_cache;
pub mod helpers;
mod pubkey_cache;
mod tests;

pub const CACHED_EPOCHS: usize = 4;

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
    ValidatorIsWithdrawable,
    InsufficientRandaoMixes,
    NoValidators,
    UnableToDetermineProducer,
    InsufficientBlockRoots,
    InsufficientIndexRoots,
    InsufficientAttestations,
    InsufficientCommittees,
    InsufficientSlashedBalances,
    NoCommitteeForShard,
    EpochCacheUninitialized(RelativeEpoch),
    PubkeyCacheInconsistent,
    PubkeyCacheIncomplete {
        cache_len: usize,
        registry_len: usize,
    },
    RelativeEpochError(RelativeEpochError),
    EpochCacheError(EpochCacheError),
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

/// The state of the `BeaconChain` at some slot.
///
/// Spec v0.5.0
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, TestRandom, Encode, Decode, TreeHash)]
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
    pub previous_epoch_attestations: Vec<PendingAttestation>,
    pub current_epoch_attestations: Vec<PendingAttestation>,
    pub previous_justified_epoch: Epoch,
    pub current_justified_epoch: Epoch,
    pub previous_justified_root: Hash256,
    pub current_justified_root: Hash256,
    pub justification_bitfield: u64,
    pub finalized_epoch: Epoch,
    pub finalized_root: Hash256,

    // Recent state
    pub latest_crosslinks: Vec<Crosslink>,
    pub latest_block_roots: Vec<Hash256>,
    pub latest_state_roots: Vec<Hash256>,
    pub latest_active_index_roots: Vec<Hash256>,
    pub latest_slashed_balances: Vec<u64>,
    pub latest_block_header: BeaconBlockHeader,
    pub historical_roots: Vec<Hash256>,

    // Ethereum 1.0 chain data
    pub latest_eth1_data: Eth1Data,
    pub eth1_data_votes: Vec<Eth1DataVote>,
    pub deposit_index: u64,

    // Caching (not in the spec)
    #[serde(default)]
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    pub cache_index_offset: usize,
    #[serde(default)]
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    pub caches: [EpochCache; CACHED_EPOCHS],
    #[serde(default)]
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    pub pubkey_cache: PubkeyCache,
}

impl BeaconState {
    /// Produce the first state of the Beacon Chain.
    ///
    /// This does not fully build a genesis beacon state, it omits processing of initial validator
    /// deposits. To obtain a full genesis beacon state, use the `BeaconStateBuilder`.
    ///
    /// Spec v0.5.0
    pub fn genesis(genesis_time: u64, latest_eth1_data: Eth1Data, spec: &ChainSpec) -> BeaconState {
        let initial_crosslink = Crosslink {
            epoch: spec.genesis_epoch,
            crosslink_data_root: spec.zero_hash,
        };

        BeaconState {
            // Misc
            slot: spec.genesis_slot,
            genesis_time,
            fork: Fork::genesis(spec),

            // Validator registry
            validator_registry: vec![], // Set later in the function.
            validator_balances: vec![], // Set later in the function.
            validator_registry_update_epoch: spec.genesis_epoch,

            // Randomness and committees
            latest_randao_mixes: vec![spec.zero_hash; spec.latest_randao_mixes_length as usize],
            previous_shuffling_start_shard: spec.genesis_start_shard,
            current_shuffling_start_shard: spec.genesis_start_shard,
            previous_shuffling_epoch: spec.genesis_epoch,
            current_shuffling_epoch: spec.genesis_epoch,
            previous_shuffling_seed: spec.zero_hash,
            current_shuffling_seed: spec.zero_hash,

            // Finality
            previous_epoch_attestations: vec![],
            current_epoch_attestations: vec![],
            previous_justified_epoch: spec.genesis_epoch,
            current_justified_epoch: spec.genesis_epoch,
            previous_justified_root: spec.zero_hash,
            current_justified_root: spec.zero_hash,
            justification_bitfield: 0,
            finalized_epoch: spec.genesis_epoch,
            finalized_root: spec.zero_hash,

            // Recent state
            latest_crosslinks: vec![initial_crosslink; spec.shard_count as usize],
            latest_block_roots: vec![spec.zero_hash; spec.slots_per_historical_root],
            latest_state_roots: vec![spec.zero_hash; spec.slots_per_historical_root],
            latest_active_index_roots: vec![spec.zero_hash; spec.latest_active_index_roots_length],
            latest_slashed_balances: vec![0; spec.latest_slashed_exit_length],
            latest_block_header: BeaconBlock::empty(spec).into_temporary_header(spec),
            historical_roots: vec![],

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
            caches: [
                EpochCache::default(),
                EpochCache::default(),
                EpochCache::default(),
                EpochCache::default(),
            ],
            pubkey_cache: PubkeyCache::default(),
        }
    }

    /// Returns the `hash_tree_root` of the state.
    ///
    /// Spec v0.5.0
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

        if self.caches[cache_index].initialized_epoch == Some(self.slot.epoch(spec.slots_per_epoch))
        {
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
        let cache_index = self.cache_index(relative_epoch);

        self.caches[cache_index] = EpochCache::initialized(&self, relative_epoch, spec)?;

        Ok(())
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
        self.caches[previous_cache_index] = EpochCache::default();
    }

    /// Returns the index of `self.caches` for some `RelativeEpoch`.
    fn cache_index(&self, relative_epoch: RelativeEpoch) -> usize {
        let base_index = match relative_epoch {
            RelativeEpoch::Previous => 0,
            RelativeEpoch::Current => 1,
            RelativeEpoch::NextWithoutRegistryChange => 2,
            RelativeEpoch::NextWithRegistryChange => 3,
        };

        (base_index + self.cache_index_offset) % CACHED_EPOCHS
    }

    /// Returns the cache for some `RelativeEpoch`. Returns an error if the cache has not been
    /// initialized.
    fn cache(&self, relative_epoch: RelativeEpoch, spec: &ChainSpec) -> Result<&EpochCache, Error> {
        let cache = &self.caches[self.cache_index(relative_epoch)];

        let epoch = relative_epoch.into_epoch(self.slot.epoch(spec.slots_per_epoch));

        if cache.initialized_epoch == Some(epoch) {
            Ok(cache)
        } else {
            Err(Error::EpochCacheUninitialized(relative_epoch))
        }
    }

    /// Updates the pubkey cache, if required.
    ///
    /// Adds all `pubkeys` from the `validator_registry` which are not already in the cache. Will
    /// never re-add a pubkey.
    pub fn update_pubkey_cache(&mut self) -> Result<(), Error> {
        for (i, validator) in self
            .validator_registry
            .iter()
            .enumerate()
            .skip(self.pubkey_cache.len())
        {
            let success = self.pubkey_cache.insert(validator.pubkey.clone(), i);
            if !success {
                return Err(Error::PubkeyCacheInconsistent);
            }
        }

        Ok(())
    }

    /// Completely drops the `pubkey_cache`, replacing it with a new, empty cache.
    pub fn drop_pubkey_cache(&mut self) {
        self.pubkey_cache = PubkeyCache::default()
    }

    /// If a validator pubkey exists in the validator registry, returns `Some(i)`, otherwise
    /// returns `None`.
    ///
    /// Requires a fully up-to-date `pubkey_cache`, returns an error if this is not the case.
    pub fn get_validator_index(&self, pubkey: &PublicKey) -> Result<Option<usize>, Error> {
        if self.pubkey_cache.len() == self.validator_registry.len() {
            Ok(self.pubkey_cache.get(pubkey))
        } else {
            Err(Error::PubkeyCacheIncomplete {
                cache_len: self.pubkey_cache.len(),
                registry_len: self.validator_registry.len(),
            })
        }
    }

    /// The epoch corresponding to `self.slot`.
    ///
    /// Spec v0.5.0
    pub fn current_epoch(&self, spec: &ChainSpec) -> Epoch {
        self.slot.epoch(spec.slots_per_epoch)
    }

    /// The epoch prior to `self.current_epoch()`.
    ///
    /// If the current epoch is the genesis epoch, the genesis_epoch is returned.
    ///
    /// Spec v0.5.0
    pub fn previous_epoch(&self, spec: &ChainSpec) -> Epoch {
        self.current_epoch(&spec) - 1
    }

    /// The epoch following `self.current_epoch()`.
    ///
    /// Spec v0.5.0
    pub fn next_epoch(&self, spec: &ChainSpec) -> Epoch {
        self.current_epoch(spec) + 1
    }

    /// Returns the active validator indices for the given epoch, assuming there is no validator
    /// registry update in the next epoch.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.5.0
    pub fn get_active_validator_indices(
        &self,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<&[usize], Error> {
        // If the slot is in the next epoch, assume there was no validator registry update.
        let relative_epoch =
            match RelativeEpoch::from_epoch(self.slot.epoch(spec.slots_per_epoch), epoch) {
                Err(RelativeEpochError::AmbiguiousNextEpoch) => {
                    Ok(RelativeEpoch::NextWithoutRegistryChange)
                }
                e => e,
            }?;

        let cache = self.cache(relative_epoch, spec)?;

        Ok(&cache.active_validator_indices)
    }

    /// Returns the crosslink committees for some slot.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.5.0
    pub fn get_crosslink_committees_at_slot(
        &self,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Result<&Vec<CrosslinkCommittee>, Error> {
        // If the slot is in the next epoch, assume there was no validator registry update.
        let relative_epoch = match RelativeEpoch::from_slot(self.slot, slot, spec) {
            Err(RelativeEpochError::AmbiguiousNextEpoch) => {
                Ok(RelativeEpoch::NextWithoutRegistryChange)
            }
            e => e,
        }?;

        let cache = self.cache(relative_epoch, spec)?;

        Ok(cache
            .get_crosslink_committees_at_slot(slot, spec)
            .ok_or_else(|| Error::SlotOutOfBounds)?)
    }

    /// Returns the crosslink committees for some shard in an epoch.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.4.0
    pub fn get_crosslink_committee_for_shard(
        &self,
        epoch: Epoch,
        shard: Shard,
        spec: &ChainSpec,
    ) -> Result<&CrosslinkCommittee, Error> {
        // If the slot is in the next epoch, assume there was no validator registry update.
        let relative_epoch = match RelativeEpoch::from_epoch(self.current_epoch(spec), epoch) {
            Err(RelativeEpochError::AmbiguiousNextEpoch) => {
                Ok(RelativeEpoch::NextWithoutRegistryChange)
            }
            e => e,
        }?;

        let cache = self.cache(relative_epoch, spec)?;

        Ok(cache
            .get_crosslink_committee_for_shard(shard, spec)
            .ok_or_else(|| Error::NoCommitteeForShard)?)
    }

    /// Return the block root at a recent `slot`.
    ///
    /// Spec v0.5.0
    pub fn get_block_root(
        &self,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Result<&Hash256, BeaconStateError> {
        if (self.slot <= slot + spec.slots_per_historical_root as u64) && (slot < self.slot) {
            self.latest_block_roots
                .get(slot.as_usize() % spec.slots_per_historical_root)
                .ok_or_else(|| Error::InsufficientBlockRoots)
        } else {
            Err(Error::EpochOutOfBounds)
        }
    }

    /// XOR-assigns the existing `epoch` randao mix with the hash of the `signature`.
    ///
    /// # Errors:
    ///
    /// See `Self::get_randao_mix`.
    ///
    /// Spec v0.5.0
    pub fn update_randao_mix(
        &mut self,
        epoch: Epoch,
        signature: &Signature,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let i = epoch.as_usize() % spec.latest_randao_mixes_length;

        let signature_hash = Hash256::from_slice(&hash(&ssz_encode(signature)));

        self.latest_randao_mixes[i] = *self.get_randao_mix(epoch, spec)? ^ signature_hash;

        Ok(())
    }

    /// Return the randao mix at a recent ``epoch``.
    ///
    /// # Errors:
    /// - `InsufficientRandaoMixes` if `self.latest_randao_mixes` is shorter than
    /// `spec.latest_randao_mixes_length`.
    /// - `EpochOutOfBounds` if the state no longer stores randao mixes for the given `epoch`.
    ///
    /// Spec v0.5.0
    pub fn get_randao_mix(&self, epoch: Epoch, spec: &ChainSpec) -> Result<&Hash256, Error> {
        let current_epoch = self.current_epoch(spec);

        if (current_epoch - (spec.latest_randao_mixes_length as u64) < epoch)
            & (epoch <= current_epoch)
        {
            self.latest_randao_mixes
                .get(epoch.as_usize() % spec.latest_randao_mixes_length)
                .ok_or_else(|| Error::InsufficientRandaoMixes)
        } else {
            Err(Error::EpochOutOfBounds)
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
            .get_randao_mix(epoch - spec.min_seed_lookahead, spec)?
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
    /// Spec v0.5.0
    pub fn get_beacon_proposer_index(
        &self,
        slot: Slot,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<usize, Error> {
        let cache = self.cache(relative_epoch, spec)?;

        let committees = cache
            .get_crosslink_committees_at_slot(slot, spec)
            .ok_or_else(|| Error::SlotOutOfBounds)?;

        let epoch = slot.epoch(spec.slots_per_epoch);

        committees
            .first()
            .ok_or(Error::UnableToDetermineProducer)
            .and_then(|first| {
                let index = epoch
                    .as_usize()
                    .checked_rem(first.committee.len())
                    .ok_or(Error::UnableToDetermineProducer)?;
                Ok(first.committee[index])
            })
    }

    /// Return the effective balance (also known as "balance at stake") for a validator with the given ``index``.
    ///
    /// Spec v0.4.0
    pub fn get_effective_balance(
        &self,
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<u64, Error> {
        let balance = self
            .validator_balances
            .get(validator_index)
            .ok_or_else(|| Error::UnknownValidator)?;
        Ok(std::cmp::min(*balance, spec.max_deposit_amount))
    }

    ///  Return the epoch at which an activation or exit triggered in ``epoch`` takes effect.
    ///
    ///  Spec v0.4.0
    pub fn get_delayed_activation_exit_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> Epoch {
        epoch + 1 + spec.activation_exit_delay
    }

    /// Activate the validator of the given ``index``.
    ///
    /// Spec v0.5.0
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
    /// Spec v0.5.0
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
    /// Spec v0.5.0
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
        let effective_balance = self.get_effective_balance(validator_index, spec)?;

        // A validator that is withdrawn cannot be slashed.
        //
        // This constraint will be lifted in Phase 0.
        if self.slot
            >= validator
                .withdrawable_epoch
                .start_slot(spec.slots_per_epoch)
        {
            return Err(Error::ValidatorIsWithdrawable);
        }

        self.exit_validator(validator_index, spec);

        self.increment_current_epoch_slashed_balances(effective_balance, spec)?;

        let whistleblower_index =
            self.get_beacon_proposer_index(self.slot, RelativeEpoch::Current, spec)?;
        let whistleblower_reward = effective_balance / spec.whistleblower_reward_quotient;

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

        Ok(())
    }

    /// Increment `self.latest_slashed_balances` with a slashing from the current epoch.
    ///
    /// Spec v0.5.0.
    fn increment_current_epoch_slashed_balances(
        &mut self,
        increment: u64,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let current_epoch = self.current_epoch(spec);

        let slashed_balances_index = current_epoch.as_usize() % spec.latest_slashed_exit_length;
        if slashed_balances_index >= self.latest_slashed_balances.len() {
            return Err(Error::InsufficientSlashedBalances);
        }

        self.latest_slashed_balances[slashed_balances_index] += increment;

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

    /// Returns the `slot`, `shard` and `committee_index` for which a validator must produce an
    /// attestation.
    ///
    /// Only reads the current epoch.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.4.0
    pub fn get_attestation_duties(
        &self,
        validator_index: usize,
        spec: &ChainSpec,
    ) -> Result<&Option<AttestationDuty>, Error> {
        let cache = self.cache(RelativeEpoch::Current, spec)?;

        Ok(cache
            .attestation_duties
            .get(validator_index)
            .ok_or_else(|| Error::UnknownValidator)?)
    }

    /// Process slashings.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.4.0
    pub fn process_slashings(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        let current_epoch = self.current_epoch(spec);
        let active_validator_indices = self.get_active_validator_indices(current_epoch, spec)?;
        let total_balance = self.get_total_balance(&active_validator_indices[..], spec)?;

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

                let effective_balance = self.get_effective_balance(index, spec)?;
                let penalty = std::cmp::max(
                    effective_balance * std::cmp::min(total_penalities * 3, total_balance)
                        / total_balance,
                    effective_balance / spec.min_penalty_quotient,
                );

                safe_sub_assign!(self.validator_balances[index], penalty);
            }
        }

        Ok(())
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
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.4.0
    pub fn update_validator_registry(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        let current_epoch = self.current_epoch(spec);
        let active_validator_indices = self.get_active_validator_indices(current_epoch, spec)?;
        let total_balance = self.get_total_balance(&active_validator_indices[..], spec)?;

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
                balance_churn += self.get_effective_balance(index, spec)?;
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
                balance_churn += self.get_effective_balance(index, spec)?;
                if balance_churn > max_balance_churn {
                    break;
                }

                self.exit_validator(index, spec);
            }
        }

        self.validator_registry_update_epoch = current_epoch;

        Ok(())
    }

    /// Iterate through the validator registry and eject active validators with balance below
    /// ``EJECTION_BALANCE``.
    ///
    /// Spec v0.5.0
    pub fn process_ejections(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        // There is an awkward double (triple?) loop here because we can't loop across the borrowed
        // active validator indices and mutate state in the one loop.
        let exitable: Vec<usize> = self
            .get_active_validator_indices(self.current_epoch(spec), spec)?
            .iter()
            .filter_map(|&i| {
                if self.validator_balances[i as usize] < spec.ejection_balance {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        for validator_index in exitable {
            self.exit_validator(validator_index, spec)
        }

        Ok(())
    }

    /// Return the combined effective balance of an array of validators.
    ///
    /// Spec v0.5.0
    pub fn get_total_balance(
        &self,
        validator_indices: &[usize],
        spec: &ChainSpec,
    ) -> Result<u64, Error> {
        validator_indices.iter().try_fold(0_u64, |acc, i| {
            self.get_effective_balance(*i, spec)
                .and_then(|bal| Ok(bal + acc))
        })
    }
}

impl From<RelativeEpochError> for Error {
    fn from(e: RelativeEpochError) -> Error {
        Error::RelativeEpochError(e)
    }
}

impl From<EpochCacheError> for Error {
    fn from(e: EpochCacheError) -> Error {
        Error::EpochCacheError(e)
    }
}
