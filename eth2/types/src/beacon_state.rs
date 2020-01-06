use self::committee_cache::get_active_validator_indices;
use self::exit_cache::ExitCache;
use crate::test_utils::TestRandom;
use crate::*;
use cached_tree_hash::{CachedTreeHash, MultiTreeHashCache, TreeHashCache};
use compare_fields_derive::CompareFields;
use eth2_hashing::hash;
use int_to_bytes::{int_to_bytes4, int_to_bytes8};
use pubkey_cache::PubkeyCache;
use serde_derive::{Deserialize, Serialize};
use ssz::ssz_encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::Unsigned, BitVector, FixedVector};
use swap_or_not_shuffle::compute_shuffled_index;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{CachedTreeHash, TreeHash};

pub use self::committee_cache::CommitteeCache;
pub use eth_spec::*;

#[macro_use]
mod committee_cache;
mod exit_cache;
mod pubkey_cache;
mod tests;

pub const CACHED_EPOCHS: usize = 3;
const MAX_RANDOM_BYTE: u64 = (1 << 8) - 1;

#[derive(Debug, PartialEq)]
pub enum Error {
    EpochOutOfBounds,
    SlotOutOfBounds,
    UnknownValidator,
    UnableToDetermineProducer,
    InvalidBitfield,
    ValidatorIsWithdrawable,
    UnableToShuffle,
    TooManyValidators,
    InsufficientValidators,
    InsufficientRandaoMixes,
    InsufficientBlockRoots,
    InsufficientIndexRoots,
    InsufficientAttestations,
    InsufficientCommittees,
    InsufficientStateRoots,
    NoCommittee {
        slot: Slot,
        index: CommitteeIndex,
    },
    ZeroSlotsPerEpoch,
    PubkeyCacheInconsistent,
    PubkeyCacheIncomplete {
        cache_len: usize,
        registry_len: usize,
    },
    PreviousCommitteeCacheUninitialized,
    CurrentCommitteeCacheUninitialized,
    RelativeEpochError(RelativeEpochError),
    CommitteeCacheUninitialized(Option<RelativeEpoch>),
    SszTypesError(ssz_types::Error),
    CachedTreeHashError(cached_tree_hash::Error),
}

/// Control whether an epoch-indexed field can be indexed at the next epoch or not.
#[derive(Debug, PartialEq, Clone, Copy)]
enum AllowNextEpoch {
    True,
    False,
}

impl AllowNextEpoch {
    fn upper_bound_of(self, current_epoch: Epoch) -> Epoch {
        match self {
            AllowNextEpoch::True => current_epoch + 1,
            AllowNextEpoch::False => current_epoch,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
pub struct BeaconTreeHashCache {
    initialized: bool,
    block_roots: TreeHashCache,
    state_roots: TreeHashCache,
    historical_roots: TreeHashCache,
    validators: MultiTreeHashCache,
    balances: TreeHashCache,
    randao_mixes: TreeHashCache,
    slashings: TreeHashCache,
}

impl BeaconTreeHashCache {
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

/// The state of the `BeaconChain` at some slot.
///
/// Spec v0.9.1
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
    CompareFields,
)]
#[serde(bound = "T: EthSpec")]
#[cached_tree_hash(type = "BeaconTreeHashCache")]
pub struct BeaconState<T>
where
    T: EthSpec,
{
    // Versioning
    pub genesis_time: u64,
    pub slot: Slot,
    pub fork: Fork,

    // History
    pub latest_block_header: BeaconBlockHeader,
    #[compare_fields(as_slice)]
    #[cached_tree_hash(block_roots)]
    pub block_roots: FixedVector<Hash256, T::SlotsPerHistoricalRoot>,
    #[compare_fields(as_slice)]
    #[cached_tree_hash(state_roots)]
    pub state_roots: FixedVector<Hash256, T::SlotsPerHistoricalRoot>,
    #[cached_tree_hash(historical_roots)]
    pub historical_roots: VariableList<Hash256, T::HistoricalRootsLimit>,

    // Ethereum 1.0 chain data
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: VariableList<Eth1Data, T::SlotsPerEth1VotingPeriod>,
    pub eth1_deposit_index: u64,

    // Registry
    #[compare_fields(as_slice)]
    #[cached_tree_hash(validators)]
    pub validators: VariableList<Validator, T::ValidatorRegistryLimit>,
    #[compare_fields(as_slice)]
    #[cached_tree_hash(balances)]
    pub balances: VariableList<u64, T::ValidatorRegistryLimit>,

    // Randomness
    #[cached_tree_hash(randao_mixes)]
    pub randao_mixes: FixedVector<Hash256, T::EpochsPerHistoricalVector>,

    // Slashings
    #[cached_tree_hash(slashings)]
    pub slashings: FixedVector<u64, T::EpochsPerSlashingsVector>,

    // Attestations
    pub previous_epoch_attestations: VariableList<PendingAttestation<T>, T::MaxPendingAttestations>,
    pub current_epoch_attestations: VariableList<PendingAttestation<T>, T::MaxPendingAttestations>,

    // Finality
    #[test_random(default)]
    pub justification_bits: BitVector<T::JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // Caching (not in the spec)
    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    pub committee_caches: [CommitteeCache; CACHED_EPOCHS],
    #[serde(skip_serializing, skip_deserializing)]
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
    pub exit_cache: ExitCache,
    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    pub tree_hash_cache: BeaconTreeHashCache,
}

impl<T: EthSpec> BeaconState<T> {
    /// Create a new BeaconState suitable for genesis.
    ///
    /// Not a complete genesis state, see `initialize_beacon_state_from_eth1`.
    ///
    /// Spec v0.9.1
    pub fn new(genesis_time: u64, eth1_data: Eth1Data, spec: &ChainSpec) -> Self {
        BeaconState {
            // Versioning
            genesis_time,
            slot: spec.genesis_slot,
            fork: spec.genesis_fork.clone(),

            // History
            latest_block_header: BeaconBlock::<T>::empty(spec).temporary_block_header(),
            block_roots: FixedVector::from_elem(Hash256::zero()),
            state_roots: FixedVector::from_elem(Hash256::zero()),
            historical_roots: VariableList::empty(),

            // Eth1
            eth1_data,
            eth1_data_votes: VariableList::empty(),
            eth1_deposit_index: 0,

            // Validator registry
            validators: VariableList::empty(), // Set later.
            balances: VariableList::empty(),   // Set later.

            // Randomness
            randao_mixes: FixedVector::from_elem(Hash256::zero()),

            // Slashings
            slashings: FixedVector::from_elem(0),

            // Attestations
            previous_epoch_attestations: VariableList::empty(),
            current_epoch_attestations: VariableList::empty(),

            // Finality
            justification_bits: BitVector::new(),
            previous_justified_checkpoint: Checkpoint::default(),
            current_justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),

            // Caching (not in spec)
            committee_caches: [
                CommitteeCache::default(),
                CommitteeCache::default(),
                CommitteeCache::default(),
            ],
            pubkey_cache: PubkeyCache::default(),
            exit_cache: ExitCache::default(),
            tree_hash_cache: BeaconTreeHashCache::default(),
        }
    }

    /// Returns the `tree_hash_root` of the state.
    ///
    /// Spec v0.9.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.tree_hash_root()[..])
    }

    pub fn historical_batch(&self) -> HistoricalBatch<T> {
        HistoricalBatch {
            block_roots: self.block_roots.clone(),
            state_roots: self.state_roots.clone(),
        }
    }

    /// If a validator pubkey exists in the validator registry, returns `Some(i)`, otherwise
    /// returns `None`.
    ///
    /// Requires a fully up-to-date `pubkey_cache`, returns an error if this is not the case.
    pub fn get_validator_index(&self, pubkey: &PublicKeyBytes) -> Result<Option<usize>, Error> {
        if self.pubkey_cache.len() == self.validators.len() {
            Ok(self.pubkey_cache.get(pubkey))
        } else {
            Err(Error::PubkeyCacheIncomplete {
                cache_len: self.pubkey_cache.len(),
                registry_len: self.validators.len(),
            })
        }
    }

    /// The epoch corresponding to `self.slot`.
    ///
    /// Spec v0.9.1
    pub fn current_epoch(&self) -> Epoch {
        self.slot.epoch(T::slots_per_epoch())
    }

    /// The epoch prior to `self.current_epoch()`.
    ///
    /// If the current epoch is the genesis epoch, the genesis_epoch is returned.
    ///
    /// Spec v0.9.1
    pub fn previous_epoch(&self) -> Epoch {
        let current_epoch = self.current_epoch();
        if current_epoch > T::genesis_epoch() {
            current_epoch - 1
        } else {
            current_epoch
        }
    }

    /// The epoch following `self.current_epoch()`.
    ///
    /// Spec v0.9.1
    pub fn next_epoch(&self) -> Epoch {
        self.current_epoch() + 1
    }

    /// Compute the number of committees at `slot`.
    ///
    /// Makes use of the committee cache and will fail if no cache exists for the slot's epoch.
    ///
    /// Spec v0.9.1
    pub fn get_committee_count_at_slot(&self, slot: Slot) -> Result<u64, Error> {
        let cache = self.committee_cache_at_slot(slot)?;
        Ok(cache.committees_per_slot() as u64)
    }

    /// Compute the number of committees in an entire epoch.
    ///
    /// Spec v0.9.1
    pub fn get_epoch_committee_count(&self, relative_epoch: RelativeEpoch) -> Result<u64, Error> {
        let cache = self.committee_cache(relative_epoch)?;
        Ok(cache.epoch_committee_count() as u64)
    }

    /// Return the cached active validator indices at some epoch.
    ///
    /// Note: the indices are shuffled (i.e., not in ascending order).
    ///
    /// Returns an error if that epoch is not cached, or the cache is not initialized.
    pub fn get_cached_active_validator_indices(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> Result<&[usize], Error> {
        let cache = self.committee_cache(relative_epoch)?;

        Ok(&cache.active_validator_indices())
    }

    /// Returns the active validator indices for the given epoch.
    ///
    /// Does not utilize the cache, performs a full iteration over the validator registry.
    ///
    /// Spec v0.9.1
    pub fn get_active_validator_indices(&self, epoch: Epoch) -> Vec<usize> {
        get_active_validator_indices(&self.validators, epoch)
    }

    /// Return the cached active validator indices at some epoch.
    ///
    /// Note: the indices are shuffled (i.e., not in ascending order).
    ///
    /// Returns an error if that epoch is not cached, or the cache is not initialized.
    pub fn get_shuffling(&self, relative_epoch: RelativeEpoch) -> Result<&[usize], Error> {
        let cache = self.committee_cache(relative_epoch)?;

        Ok(cache.shuffling())
    }

    /// Get the Beacon committee at the given slot and index.
    ///
    /// Utilises the committee cache.
    ///
    /// Spec v0.9.1
    pub fn get_beacon_committee(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<BeaconCommittee, Error> {
        let epoch = slot.epoch(T::slots_per_epoch());
        let relative_epoch = RelativeEpoch::from_epoch(self.current_epoch(), epoch)?;
        let cache = self.committee_cache(relative_epoch)?;

        cache
            .get_beacon_committee(slot, index)
            .ok_or(Error::NoCommittee { slot, index })
    }

    /// Get all of the Beacon committees at a given slot.
    ///
    /// Utilises the committee cache.
    ///
    /// Spec v0.9.1
    pub fn get_beacon_committees_at_slot(&self, slot: Slot) -> Result<Vec<BeaconCommittee>, Error> {
        let cache = self.committee_cache_at_slot(slot)?;
        cache.get_beacon_committees_at_slot(slot)
    }

    /// Get all of the Beacon committees at a given relative epoch.
    ///
    /// Utilises the committee cache.
    ///
    /// Spec v0.9.1
    pub fn get_beacon_committees_at_epoch(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> Result<Vec<BeaconCommittee>, Error> {
        let cache = self.committee_cache(relative_epoch)?;
        cache.get_all_beacon_committees()
    }

    /// Compute the proposer (not necessarily for the Beacon chain) from a list of indices.
    ///
    /// Spec v0.9.1
    // NOTE: be sure to test this bad boy.
    pub fn compute_proposer_index(
        &self,
        indices: &[usize],
        seed: &[u8],
        spec: &ChainSpec,
    ) -> Result<usize, Error> {
        if indices.is_empty() {
            return Err(Error::InsufficientValidators);
        }

        let mut i = 0;
        loop {
            let candidate_index = indices[compute_shuffled_index(
                i % indices.len(),
                indices.len(),
                seed,
                spec.shuffle_round_count,
            )
            .ok_or(Error::UnableToShuffle)?];
            let random_byte = {
                let mut preimage = seed.to_vec();
                preimage.append(&mut int_to_bytes8((i / 32) as u64));
                let hash = hash(&preimage);
                hash[i % 32]
            };
            let effective_balance = self.validators[candidate_index].effective_balance;
            if effective_balance * MAX_RANDOM_BYTE
                >= spec.max_effective_balance * u64::from(random_byte)
            {
                return Ok(candidate_index);
            }
            i += 1;
        }
    }

    /// Returns the beacon proposer index for the `slot` in the given `relative_epoch`.
    ///
    /// Spec v0.9.1
    pub fn get_beacon_proposer_index(&self, slot: Slot, spec: &ChainSpec) -> Result<usize, Error> {
        let epoch = slot.epoch(T::slots_per_epoch());
        let seed = self.get_beacon_proposer_seed(slot, spec)?;
        let indices = self.get_active_validator_indices(epoch);

        self.compute_proposer_index(&indices, &seed, spec)
    }

    /// Compute the seed to use for the beacon proposer selection at the given `slot`.
    ///
    /// Spec v0.9.1
    fn get_beacon_proposer_seed(&self, slot: Slot, spec: &ChainSpec) -> Result<Vec<u8>, Error> {
        let epoch = slot.epoch(T::slots_per_epoch());
        let mut preimage = self
            .get_seed(epoch, Domain::BeaconProposer, spec)?
            .as_bytes()
            .to_vec();
        preimage.append(&mut int_to_bytes8(slot.as_u64()));
        Ok(hash(&preimage))
    }

    /// Safely obtains the index for latest block roots, given some `slot`.
    ///
    /// Spec v0.9.1
    fn get_latest_block_roots_index(&self, slot: Slot) -> Result<usize, Error> {
        if (slot < self.slot) && (self.slot <= slot + self.block_roots.len() as u64) {
            Ok(slot.as_usize() % self.block_roots.len())
        } else {
            Err(BeaconStateError::SlotOutOfBounds)
        }
    }

    /// Return the block root at a recent `slot`.
    ///
    /// Spec v0.9.1
    pub fn get_block_root(&self, slot: Slot) -> Result<&Hash256, BeaconStateError> {
        let i = self.get_latest_block_roots_index(slot)?;
        Ok(&self.block_roots[i])
    }

    /// Return the block root at a recent `epoch`.
    ///
    /// Spec v0.9.1
    // NOTE: the spec calls this get_block_root
    pub fn get_block_root_at_epoch(&self, epoch: Epoch) -> Result<&Hash256, BeaconStateError> {
        self.get_block_root(epoch.start_slot(T::slots_per_epoch()))
    }

    /// Sets the block root for some given slot.
    ///
    /// Spec v0.9.1
    pub fn set_block_root(
        &mut self,
        slot: Slot,
        block_root: Hash256,
    ) -> Result<(), BeaconStateError> {
        let i = self.get_latest_block_roots_index(slot)?;
        self.block_roots[i] = block_root;
        Ok(())
    }

    /// Fill `randao_mixes` with
    pub fn fill_randao_mixes_with(&mut self, index_root: Hash256) {
        self.randao_mixes = FixedVector::from_elem(index_root);
    }

    /// Safely obtains the index for `randao_mixes`
    ///
    /// Spec v0.9.1
    fn get_randao_mix_index(
        &self,
        epoch: Epoch,
        allow_next_epoch: AllowNextEpoch,
    ) -> Result<usize, Error> {
        let current_epoch = self.current_epoch();
        let len = T::EpochsPerHistoricalVector::to_u64();

        if current_epoch < epoch + len && epoch <= allow_next_epoch.upper_bound_of(current_epoch) {
            Ok(epoch.as_usize() % len as usize)
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
    /// Spec v0.9.1
    pub fn update_randao_mix(&mut self, epoch: Epoch, signature: &Signature) -> Result<(), Error> {
        let i = epoch.as_usize() % T::EpochsPerHistoricalVector::to_usize();

        let signature_hash = Hash256::from_slice(&hash(&ssz_encode(signature)));

        self.randao_mixes[i] = *self.get_randao_mix(epoch)? ^ signature_hash;

        Ok(())
    }

    /// Return the randao mix at a recent ``epoch``.
    ///
    /// Spec v0.9.1
    pub fn get_randao_mix(&self, epoch: Epoch) -> Result<&Hash256, Error> {
        let i = self.get_randao_mix_index(epoch, AllowNextEpoch::False)?;
        Ok(&self.randao_mixes[i])
    }

    /// Set the randao mix at a recent ``epoch``.
    ///
    /// Spec v0.9.1
    pub fn set_randao_mix(&mut self, epoch: Epoch, mix: Hash256) -> Result<(), Error> {
        let i = self.get_randao_mix_index(epoch, AllowNextEpoch::True)?;
        self.randao_mixes[i] = mix;
        Ok(())
    }

    /// Safely obtains the index for latest state roots, given some `slot`.
    ///
    /// Spec v0.9.1
    fn get_latest_state_roots_index(&self, slot: Slot) -> Result<usize, Error> {
        if (slot < self.slot) && (self.slot <= slot + Slot::from(self.state_roots.len())) {
            Ok(slot.as_usize() % self.state_roots.len())
        } else {
            Err(BeaconStateError::SlotOutOfBounds)
        }
    }

    /// Gets the state root for some slot.
    ///
    /// Spec v0.9.1
    pub fn get_state_root(&self, slot: Slot) -> Result<&Hash256, Error> {
        let i = self.get_latest_state_roots_index(slot)?;
        Ok(&self.state_roots[i])
    }

    /// Gets the oldest (earliest slot) state root.
    ///
    /// Spec v0.9.1
    pub fn get_oldest_state_root(&self) -> Result<&Hash256, Error> {
        let i =
            self.get_latest_state_roots_index(self.slot - Slot::from(self.state_roots.len()))?;
        Ok(&self.state_roots[i])
    }

    /// Gets the oldest (earliest slot) block root.
    ///
    /// Spec v0.9.1
    pub fn get_oldest_block_root(&self) -> Result<&Hash256, Error> {
        let i = self.get_latest_block_roots_index(self.slot - self.block_roots.len() as u64)?;
        Ok(&self.block_roots[i])
    }

    /// Sets the latest state root for slot.
    ///
    /// Spec v0.9.1
    pub fn set_state_root(&mut self, slot: Slot, state_root: Hash256) -> Result<(), Error> {
        let i = self.get_latest_state_roots_index(slot)?;
        self.state_roots[i] = state_root;
        Ok(())
    }

    /// Safely obtain the index for `slashings`, given some `epoch`.
    ///
    /// Spec v0.9.1
    fn get_slashings_index(
        &self,
        epoch: Epoch,
        allow_next_epoch: AllowNextEpoch,
    ) -> Result<usize, Error> {
        // We allow the slashings vector to be accessed at any cached epoch at or before
        // the current epoch, or the next epoch if `AllowNextEpoch::True` is passed.
        let current_epoch = self.current_epoch();
        if current_epoch < epoch + T::EpochsPerSlashingsVector::to_u64()
            && epoch <= allow_next_epoch.upper_bound_of(current_epoch)
        {
            Ok(epoch.as_usize() % T::EpochsPerSlashingsVector::to_usize())
        } else {
            Err(Error::EpochOutOfBounds)
        }
    }

    /// Get a reference to the entire `slashings` vector.
    ///
    /// Spec v0.9.1
    pub fn get_all_slashings(&self) -> &[u64] {
        &self.slashings
    }

    /// Get the total slashed balances for some epoch.
    ///
    /// Spec v0.9.1
    pub fn get_slashings(&self, epoch: Epoch) -> Result<u64, Error> {
        let i = self.get_slashings_index(epoch, AllowNextEpoch::False)?;
        Ok(self.slashings[i])
    }

    /// Set the total slashed balances for some epoch.
    ///
    /// Spec v0.9.1
    pub fn set_slashings(&mut self, epoch: Epoch, value: u64) -> Result<(), Error> {
        let i = self.get_slashings_index(epoch, AllowNextEpoch::True)?;
        self.slashings[i] = value;
        Ok(())
    }

    /// Get the attestations from the current or previous epoch.
    ///
    /// Spec v0.9.1
    pub fn get_matching_source_attestations(
        &self,
        epoch: Epoch,
    ) -> Result<&[PendingAttestation<T>], Error> {
        if epoch == self.current_epoch() {
            Ok(&self.current_epoch_attestations)
        } else if epoch == self.previous_epoch() {
            Ok(&self.previous_epoch_attestations)
        } else {
            Err(Error::EpochOutOfBounds)
        }
    }

    /// Generate a seed for the given `epoch`.
    ///
    /// Spec v0.9.1
    pub fn get_seed(
        &self,
        epoch: Epoch,
        domain_type: Domain,
        spec: &ChainSpec,
    ) -> Result<Hash256, Error> {
        // Bypass the safe getter for RANDAO so we can gracefully handle the scenario where `epoch
        // == 0`.
        let mix = {
            let i = epoch + T::EpochsPerHistoricalVector::to_u64() - spec.min_seed_lookahead - 1;
            self.randao_mixes[i.as_usize() % self.randao_mixes.len()]
        };
        let domain_bytes = int_to_bytes4(spec.get_domain_constant(domain_type));
        let epoch_bytes = int_to_bytes8(epoch.as_u64());

        const NUM_DOMAIN_BYTES: usize = 4;
        const NUM_EPOCH_BYTES: usize = 8;
        const NUM_MIX_BYTES: usize = 32;

        let mut preimage = [0; NUM_DOMAIN_BYTES + NUM_EPOCH_BYTES + NUM_MIX_BYTES];
        preimage[0..NUM_DOMAIN_BYTES].copy_from_slice(&domain_bytes);
        preimage[NUM_DOMAIN_BYTES..NUM_DOMAIN_BYTES + NUM_EPOCH_BYTES]
            .copy_from_slice(&epoch_bytes);
        preimage[NUM_DOMAIN_BYTES + NUM_EPOCH_BYTES..].copy_from_slice(mix.as_bytes());

        Ok(Hash256::from_slice(&hash(&preimage)))
    }

    /// Return the effective balance (also known as "balance at stake") for a validator with the given ``index``.
    ///
    /// Spec v0.9.1
    pub fn get_effective_balance(
        &self,
        validator_index: usize,
        _spec: &ChainSpec,
    ) -> Result<u64, Error> {
        self.validators
            .get(validator_index)
            .map(|v| v.effective_balance)
            .ok_or_else(|| Error::UnknownValidator)
    }

    ///  Return the epoch at which an activation or exit triggered in ``epoch`` takes effect.
    ///
    ///  Spec v0.9.1
    pub fn compute_activation_exit_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> Epoch {
        epoch + 1 + spec.max_seed_lookahead
    }

    /// Return the churn limit for the current epoch (number of validators who can leave per epoch).
    ///
    /// Uses the epoch cache, and will error if it isn't initialized.
    ///
    /// Spec v0.9.1
    pub fn get_churn_limit(&self, spec: &ChainSpec) -> Result<u64, Error> {
        Ok(std::cmp::max(
            spec.min_per_epoch_churn_limit,
            self.committee_cache(RelativeEpoch::Current)?
                .active_validator_count() as u64
                / spec.churn_limit_quotient,
        ))
    }

    /// Returns the `slot`, `index` and `committee_position` for which a validator must produce an
    /// attestation.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.9.1
    pub fn get_attestation_duties(
        &self,
        validator_index: usize,
        relative_epoch: RelativeEpoch,
    ) -> Result<Option<AttestationDuty>, Error> {
        let cache = self.committee_cache(relative_epoch)?;

        Ok(cache.get_attestation_duties(validator_index))
    }

    /// Return the combined effective balance of an array of validators.
    ///
    /// Spec v0.9.1
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
        self.build_committee_cache(RelativeEpoch::Previous, spec)?;
        self.build_committee_cache(RelativeEpoch::Current, spec)?;
        self.build_committee_cache(RelativeEpoch::Next, spec)?;
        self.update_pubkey_cache()?;
        self.build_tree_hash_cache()?;
        self.exit_cache.build_from_registry(&self.validators, spec);

        Ok(())
    }

    /// Drop all caches on the state.
    pub fn drop_all_caches(&mut self) {
        self.drop_committee_cache(RelativeEpoch::Previous);
        self.drop_committee_cache(RelativeEpoch::Current);
        self.drop_committee_cache(RelativeEpoch::Next);
        self.drop_pubkey_cache();
        self.drop_tree_hash_cache();
        self.exit_cache = ExitCache::default();
    }

    /// Build an epoch cache, unless it is has already been built.
    pub fn build_committee_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let i = Self::committee_cache_index(relative_epoch);

        if self.committee_caches[i]
            .is_initialized_at(relative_epoch.into_epoch(self.current_epoch()))
        {
            Ok(())
        } else {
            self.force_build_committee_cache(relative_epoch, spec)
        }
    }

    /// Always builds the previous epoch cache, even if it is already initialized.
    pub fn force_build_committee_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let epoch = relative_epoch.into_epoch(self.current_epoch());

        self.committee_caches[Self::committee_cache_index(relative_epoch)] =
            CommitteeCache::initialized(&self, epoch, spec)?;
        Ok(())
    }

    /// Advances the cache for this state into the next epoch.
    ///
    /// This should be used if the `slot` of this state is advanced beyond an epoch boundary.
    ///
    /// Note: whilst this function will preserve already-built caches, it will not build any.
    pub fn advance_caches(&mut self) {
        let caches = &mut self.committee_caches[..];
        caches.rotate_left(1);

        let next = Self::committee_cache_index(RelativeEpoch::Next);
        caches[next] = CommitteeCache::default();
    }

    fn committee_cache_index(relative_epoch: RelativeEpoch) -> usize {
        match relative_epoch {
            RelativeEpoch::Previous => 0,
            RelativeEpoch::Current => 1,
            RelativeEpoch::Next => 2,
        }
    }

    /// Get the committee cache for some `slot`.
    ///
    /// Return an error if the cache for the slot's epoch is not initialized.
    fn committee_cache_at_slot(&self, slot: Slot) -> Result<&CommitteeCache, Error> {
        let epoch = slot.epoch(T::slots_per_epoch());
        let relative_epoch = RelativeEpoch::from_epoch(self.current_epoch(), epoch)?;
        self.committee_cache(relative_epoch)
    }

    /// Returns the cache for some `RelativeEpoch`. Returns an error if the cache has not been
    /// initialized.
    fn committee_cache(&self, relative_epoch: RelativeEpoch) -> Result<&CommitteeCache, Error> {
        let cache = &self.committee_caches[Self::committee_cache_index(relative_epoch)];

        if cache.is_initialized_at(relative_epoch.into_epoch(self.current_epoch())) {
            Ok(cache)
        } else {
            Err(Error::CommitteeCacheUninitialized(Some(relative_epoch)))
        }
    }

    /// Drops the cache, leaving it in an uninitialized state.
    fn drop_committee_cache(&mut self, relative_epoch: RelativeEpoch) {
        self.committee_caches[Self::committee_cache_index(relative_epoch)] =
            CommitteeCache::default();
    }

    /// Updates the pubkey cache, if required.
    ///
    /// Adds all `pubkeys` from the `validators` which are not already in the cache. Will
    /// never re-add a pubkey.
    pub fn update_pubkey_cache(&mut self) -> Result<(), Error> {
        for (i, validator) in self
            .validators
            .iter()
            .enumerate()
            .skip(self.pubkey_cache.len())
        {
            let success = self.pubkey_cache.insert(validator.pubkey.clone().into(), i);
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

    /// Initialize but don't fill the tree hash cache, if it isn't already initialized.
    pub fn initialize_tree_hash_cache(&mut self) {
        if !self.tree_hash_cache.initialized {
            self.tree_hash_cache = Self::new_tree_hash_cache();
        }
    }

    /// Build and update the tree hash cache if it isn't already initialized.
    pub fn build_tree_hash_cache(&mut self) -> Result<(), Error> {
        self.update_tree_hash_cache().map(|_| ())
    }

    /// Build the tree hash cache, with blatant disregard for any existing cache.
    pub fn force_build_tree_hash_cache(&mut self) -> Result<(), Error> {
        self.tree_hash_cache.initialized = false;
        self.build_tree_hash_cache()
    }

    /// Compute the tree hash root of the state using the tree hash cache.
    ///
    /// Initialize the tree hash cache if it isn't already initialized.
    pub fn update_tree_hash_cache(&mut self) -> Result<Hash256, Error> {
        self.initialize_tree_hash_cache();

        let mut cache = std::mem::replace(&mut self.tree_hash_cache, <_>::default());
        let result = self.recalculate_tree_hash_root(&mut cache);
        std::mem::replace(&mut self.tree_hash_cache, cache);

        Ok(result?)
    }

    /// Completely drops the tree hash cache, replacing it with a new, empty cache.
    pub fn drop_tree_hash_cache(&mut self) {
        self.tree_hash_cache = BeaconTreeHashCache::default();
    }

    pub fn clone_without_caches(&self) -> Self {
        BeaconState {
            genesis_time: self.genesis_time,
            slot: self.slot,
            fork: self.fork.clone(),
            latest_block_header: self.latest_block_header.clone(),
            block_roots: self.block_roots.clone(),
            state_roots: self.state_roots.clone(),
            historical_roots: self.historical_roots.clone(),
            eth1_data: self.eth1_data.clone(),
            eth1_data_votes: self.eth1_data_votes.clone(),
            eth1_deposit_index: self.eth1_deposit_index,
            validators: self.validators.clone(),
            balances: self.balances.clone(),
            randao_mixes: self.randao_mixes.clone(),
            slashings: self.slashings.clone(),
            previous_epoch_attestations: self.previous_epoch_attestations.clone(),
            current_epoch_attestations: self.current_epoch_attestations.clone(),
            justification_bits: self.justification_bits.clone(),
            previous_justified_checkpoint: self.previous_justified_checkpoint.clone(),
            current_justified_checkpoint: self.current_justified_checkpoint.clone(),
            finalized_checkpoint: self.finalized_checkpoint.clone(),
            committee_caches: [
                CommitteeCache::default(),
                CommitteeCache::default(),
                CommitteeCache::default(),
            ],
            pubkey_cache: PubkeyCache::default(),
            exit_cache: ExitCache::default(),
            tree_hash_cache: BeaconTreeHashCache::default(),
        }
    }
}

impl From<RelativeEpochError> for Error {
    fn from(e: RelativeEpochError) -> Error {
        Error::RelativeEpochError(e)
    }
}

impl From<ssz_types::Error> for Error {
    fn from(e: ssz_types::Error) -> Error {
        Error::SszTypesError(e)
    }
}

impl From<cached_tree_hash::Error> for Error {
    fn from(e: cached_tree_hash::Error) -> Error {
        Error::CachedTreeHashError(e)
    }
}
