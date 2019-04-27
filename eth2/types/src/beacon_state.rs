use self::epoch_cache::{get_active_validator_indices, EpochCache, Error as EpochCacheError};
use crate::test_utils::TestRandom;
use crate::*;
use cached_tree_hash::{Error as TreeHashCacheError, TreeHashCache};
use int_to_bytes::int_to_bytes32;
use pubkey_cache::PubkeyCache;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use ssz::{hash, ssz_encode};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{CachedTreeHash, TreeHash};

mod epoch_cache;
mod pubkey_cache;
mod tests;

pub const CACHED_EPOCHS: usize = 4;

#[derive(Debug, PartialEq)]
pub enum Error {
    EpochOutOfBounds,
    SlotOutOfBounds,
    ShardOutOfBounds,
    UnknownValidator,
    UnableToDetermineProducer,
    InvalidBitfield,
    ValidatorIsWithdrawable,
    InsufficientRandaoMixes,
    InsufficientBlockRoots,
    InsufficientIndexRoots,
    InsufficientAttestations,
    InsufficientCommittees,
    InsufficientSlashedBalances,
    InsufficientStateRoots,
    NoCommitteeForShard,
    PubkeyCacheInconsistent,
    PubkeyCacheIncomplete {
        cache_len: usize,
        registry_len: usize,
    },
    EpochCacheUninitialized(RelativeEpoch),
    RelativeEpochError(RelativeEpochError),
    EpochCacheError(EpochCacheError),
    TreeHashCacheError(TreeHashCacheError),
}

/// The state of the `BeaconChain` at some slot.
///
/// Spec v0.5.1
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TestRandom,
    Encode,
    Decode,
    TreeHash,
    CachedTreeHash,
)]
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
    pub latest_randao_mixes: TreeHashVector<Hash256>,
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
    pub latest_crosslinks: TreeHashVector<Crosslink>,
    pub latest_block_roots: TreeHashVector<Hash256>,
    latest_state_roots: TreeHashVector<Hash256>,
    latest_active_index_roots: TreeHashVector<Hash256>,
    latest_slashed_balances: TreeHashVector<u64>,
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
    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    pub tree_hash_cache: TreeHashCache,
}

impl BeaconState {
    /// Produce the first state of the Beacon Chain.
    ///
    /// This does not fully build a genesis beacon state, it omits processing of initial validator
    /// deposits. To obtain a full genesis beacon state, use the `BeaconStateBuilder`.
    ///
    /// Spec v0.5.1
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
            latest_randao_mixes: vec![spec.zero_hash; spec.latest_randao_mixes_length as usize]
                .into(),
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
            latest_crosslinks: vec![initial_crosslink; spec.shard_count as usize].into(),
            latest_block_roots: vec![spec.zero_hash; spec.slots_per_historical_root].into(),
            latest_state_roots: vec![spec.zero_hash; spec.slots_per_historical_root].into(),
            latest_active_index_roots: vec![spec.zero_hash; spec.latest_active_index_roots_length]
                .into(),
            latest_slashed_balances: vec![0; spec.latest_slashed_exit_length].into(),
            latest_block_header: BeaconBlock::empty(spec).temporary_block_header(spec),
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
            tree_hash_cache: TreeHashCache::default(),
        }
    }

    /// Returns the `tree_hash_root` of the state.
    ///
    /// Spec v0.5.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.tree_hash_root()[..])
    }

    pub fn historical_batch(&self) -> HistoricalBatch {
        HistoricalBatch {
            block_roots: self.latest_block_roots.clone(),
            state_roots: self.latest_state_roots.clone(),
        }
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
    /// Spec v0.5.1
    pub fn current_epoch(&self, spec: &ChainSpec) -> Epoch {
        self.slot.epoch(spec.slots_per_epoch)
    }

    /// The epoch prior to `self.current_epoch()`.
    ///
    /// If the current epoch is the genesis epoch, the genesis_epoch is returned.
    ///
    /// Spec v0.5.1
    pub fn previous_epoch(&self, spec: &ChainSpec) -> Epoch {
        self.current_epoch(&spec) - 1
    }

    /// The epoch following `self.current_epoch()`.
    ///
    /// Spec v0.5.1
    pub fn next_epoch(&self, spec: &ChainSpec) -> Epoch {
        self.current_epoch(spec) + 1
    }

    /// Returns the active validator indices for the given epoch, assuming there is no validator
    /// registry update in the next epoch.
    ///
    /// This uses the cache, so it saves an iteration over the validator registry, however it can
    /// not return a result for any epoch before the previous epoch.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.5.1
    pub fn get_cached_active_validator_indices(
        &self,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<&[usize], Error> {
        let cache = self.cache(relative_epoch, spec)?;

        Ok(&cache.active_validator_indices)
    }

    /// Returns the active validator indices for the given epoch.
    ///
    /// Does not utilize the cache, performs a full iteration over the validator registry.
    ///
    /// Spec v0.5.1
    pub fn get_active_validator_indices(&self, epoch: Epoch) -> Vec<usize> {
        get_active_validator_indices(&self.validator_registry, epoch)
    }

    /// Returns the crosslink committees for some slot.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.5.1
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
    /// Spec v0.5.1
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

    /// Returns the beacon proposer index for the `slot`.
    ///
    /// If the state does not contain an index for a beacon proposer at the requested `slot`, then `None` is returned.
    ///
    /// Spec v0.5.1
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

    /// Safely obtains the index for latest block roots, given some `slot`.
    ///
    /// Spec v0.5.1
    fn get_latest_block_roots_index(&self, slot: Slot, spec: &ChainSpec) -> Result<usize, Error> {
        if (slot < self.slot) && (self.slot <= slot + spec.slots_per_historical_root as u64) {
            let i = slot.as_usize() % spec.slots_per_historical_root;
            if i >= self.latest_block_roots.len() {
                Err(Error::InsufficientStateRoots)
            } else {
                Ok(i)
            }
        } else {
            Err(BeaconStateError::SlotOutOfBounds)
        }
    }

    /// Return the block root at a recent `slot`.
    ///
    /// Spec v0.5.1
    pub fn get_block_root(
        &self,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Result<&Hash256, BeaconStateError> {
        let i = self.get_latest_block_roots_index(slot, spec)?;
        Ok(&self.latest_block_roots[i])
    }

    /// Sets the block root for some given slot.
    ///
    /// Spec v0.5.1
    pub fn set_block_root(
        &mut self,
        slot: Slot,
        block_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), BeaconStateError> {
        let i = self.get_latest_block_roots_index(slot, spec)?;
        self.latest_block_roots[i] = block_root;
        Ok(())
    }

    /// Safely obtains the index for `latest_randao_mixes`
    ///
    /// Spec v0.5.1
    fn get_randao_mix_index(&self, epoch: Epoch, spec: &ChainSpec) -> Result<usize, Error> {
        let current_epoch = self.current_epoch(spec);

        if (current_epoch - (spec.latest_randao_mixes_length as u64) < epoch)
            & (epoch <= current_epoch)
        {
            let i = epoch.as_usize() % spec.latest_randao_mixes_length;
            if i < self.latest_randao_mixes.len() {
                Ok(i)
            } else {
                Err(Error::InsufficientRandaoMixes)
            }
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
    /// Spec v0.5.1
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
    /// Spec v0.5.1
    pub fn get_randao_mix(&self, epoch: Epoch, spec: &ChainSpec) -> Result<&Hash256, Error> {
        let i = self.get_randao_mix_index(epoch, spec)?;
        Ok(&self.latest_randao_mixes[i])
    }

    /// Set the randao mix at a recent ``epoch``.
    ///
    /// Spec v0.5.1
    pub fn set_randao_mix(
        &mut self,
        epoch: Epoch,
        mix: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let i = self.get_randao_mix_index(epoch, spec)?;
        self.latest_randao_mixes[i] = mix;
        Ok(())
    }

    /// Safely obtains the index for `latest_active_index_roots`, given some `epoch`.
    ///
    /// Spec v0.5.1
    fn get_active_index_root_index(&self, epoch: Epoch, spec: &ChainSpec) -> Result<usize, Error> {
        let current_epoch = self.current_epoch(spec);

        if (current_epoch - spec.latest_active_index_roots_length as u64
            + spec.activation_exit_delay
            < epoch)
            & (epoch <= current_epoch + spec.activation_exit_delay)
        {
            let i = epoch.as_usize() % spec.latest_active_index_roots_length;
            if i < self.latest_active_index_roots.len() {
                Ok(i)
            } else {
                Err(Error::InsufficientIndexRoots)
            }
        } else {
            Err(Error::EpochOutOfBounds)
        }
    }

    /// Return the `active_index_root` at a recent `epoch`.
    ///
    /// Spec v0.5.1
    pub fn get_active_index_root(&self, epoch: Epoch, spec: &ChainSpec) -> Result<Hash256, Error> {
        let i = self.get_active_index_root_index(epoch, spec)?;
        Ok(self.latest_active_index_roots[i])
    }

    /// Set the `active_index_root` at a recent `epoch`.
    ///
    /// Spec v0.5.1
    pub fn set_active_index_root(
        &mut self,
        epoch: Epoch,
        index_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let i = self.get_active_index_root_index(epoch, spec)?;
        self.latest_active_index_roots[i] = index_root;
        Ok(())
    }

    /// Replace `active_index_roots` with clones of `index_root`.
    ///
    /// Spec v0.5.1
    pub fn fill_active_index_roots_with(&mut self, index_root: Hash256, spec: &ChainSpec) {
        self.latest_active_index_roots =
            vec![index_root; spec.latest_active_index_roots_length as usize].into()
    }

    /// Safely obtains the index for latest state roots, given some `slot`.
    ///
    /// Spec v0.5.1
    fn get_latest_state_roots_index(&self, slot: Slot, spec: &ChainSpec) -> Result<usize, Error> {
        if (slot < self.slot) && (self.slot <= slot + spec.slots_per_historical_root as u64) {
            let i = slot.as_usize() % spec.slots_per_historical_root;
            if i >= self.latest_state_roots.len() {
                Err(Error::InsufficientStateRoots)
            } else {
                Ok(i)
            }
        } else {
            Err(BeaconStateError::SlotOutOfBounds)
        }
    }

    /// Gets the state root for some slot.
    ///
    /// Spec v0.5.1
    pub fn get_state_root(&mut self, slot: Slot, spec: &ChainSpec) -> Result<&Hash256, Error> {
        let i = self.get_latest_state_roots_index(slot, spec)?;
        Ok(&self.latest_state_roots[i])
    }

    /// Sets the latest state root for slot.
    ///
    /// Spec v0.5.1
    pub fn set_state_root(
        &mut self,
        slot: Slot,
        state_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let i = self.get_latest_state_roots_index(slot, spec)?;
        self.latest_state_roots[i] = state_root;
        Ok(())
    }

    /// Safely obtains the index for `latest_slashed_balances`, given some `epoch`.
    ///
    /// Spec v0.5.1
    fn get_slashed_balance_index(&self, epoch: Epoch, spec: &ChainSpec) -> Result<usize, Error> {
        let i = epoch.as_usize() % spec.latest_slashed_exit_length;

        // NOTE: the validity of the epoch is not checked. It is not in the spec but it's probably
        // useful to have.
        if i < self.latest_slashed_balances.len() {
            Ok(i)
        } else {
            Err(Error::InsufficientSlashedBalances)
        }
    }

    /// Gets the total slashed balances for some epoch.
    ///
    /// Spec v0.5.1
    pub fn get_slashed_balance(&self, epoch: Epoch, spec: &ChainSpec) -> Result<u64, Error> {
        let i = self.get_slashed_balance_index(epoch, spec)?;
        Ok(self.latest_slashed_balances[i])
    }

    /// Sets the total slashed balances for some epoch.
    ///
    /// Spec v0.5.1
    pub fn set_slashed_balance(
        &mut self,
        epoch: Epoch,
        balance: u64,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let i = self.get_slashed_balance_index(epoch, spec)?;
        self.latest_slashed_balances[i] = balance;
        Ok(())
    }

    /// Generate a seed for the given `epoch`.
    ///
    /// Spec v0.5.1
    pub fn generate_seed(&self, epoch: Epoch, spec: &ChainSpec) -> Result<Hash256, Error> {
        let mut input = self
            .get_randao_mix(epoch - spec.min_seed_lookahead, spec)?
            .as_bytes()
            .to_vec();

        input.append(&mut self.get_active_index_root(epoch, spec)?.as_bytes().to_vec());

        input.append(&mut int_to_bytes32(epoch.as_u64()));

        Ok(Hash256::from_slice(&hash(&input[..])[..]))
    }

    /// Return the effective balance (also known as "balance at stake") for a validator with the given ``index``.
    ///
    /// Spec v0.5.1
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
    ///  Spec v0.5.1
    pub fn get_delayed_activation_exit_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> Epoch {
        epoch + 1 + spec.activation_exit_delay
    }

    /// Initiate an exit for the validator of the given `index`.
    ///
    /// Spec v0.5.1
    pub fn initiate_validator_exit(&mut self, validator_index: usize) {
        self.validator_registry[validator_index].initiated_exit = true;
    }

    /// Returns the `slot`, `shard` and `committee_index` for which a validator must produce an
    /// attestation.
    ///
    /// Only reads the current epoch.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.5.1
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

    /// Return the combined effective balance of an array of validators.
    ///
    /// Spec v0.5.1
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

    /// Build all the caches, if they need to be built.
    pub fn build_all_caches(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        self.build_epoch_cache(RelativeEpoch::Previous, spec)?;
        self.build_epoch_cache(RelativeEpoch::Current, spec)?;
        self.build_epoch_cache(RelativeEpoch::NextWithoutRegistryChange, spec)?;
        self.build_epoch_cache(RelativeEpoch::NextWithRegistryChange, spec)?;
        self.update_pubkey_cache()?;
        self.update_tree_hash_cache()?;

        Ok(())
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

    /// Update the tree hash cache, building it for the first time if it is empty.
    ///
    /// Returns the `tree_hash_root` resulting from the update. This root can be considered the
    /// canonical root of `self`.
    pub fn update_tree_hash_cache(&mut self) -> Result<Hash256, Error> {
        if self.tree_hash_cache.is_empty() {
            self.tree_hash_cache = TreeHashCache::new(self, 0)?;
        } else {
            // Move the cache outside of `self` to satisfy the borrow checker.
            let mut cache = std::mem::replace(&mut self.tree_hash_cache, TreeHashCache::default());

            cache.update(self)?;

            // Move the updated cache back into `self`.
            self.tree_hash_cache = cache
        }

        self.cached_tree_hash_root()
    }

    /// Returns the tree hash root determined by the last execution of `self.update_tree_hash_cache(..)`.
    ///
    /// Note: does _not_ update the cache and may return an outdated root.
    ///
    /// Returns an error if the cache is not initialized or if an error is encountered during the
    /// cache update.
    pub fn cached_tree_hash_root(&self) -> Result<Hash256, Error> {
        self.tree_hash_cache
            .root()
            .and_then(|b| Ok(Hash256::from_slice(b)))
            .map_err(|e| e.into())
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

impl From<TreeHashCacheError> for Error {
    fn from(e: TreeHashCacheError) -> Error {
        Error::TreeHashCacheError(e)
    }
}
