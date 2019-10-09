use self::committee_cache::get_active_validator_indices;
use self::exit_cache::ExitCache;
use crate::test_utils::TestRandom;
use crate::*;
use compare_fields_derive::CompareFields;
use eth2_hashing::hash;
use int_to_bytes::{int_to_bytes32, int_to_bytes8};
use pubkey_cache::PubkeyCache;
use serde_derive::{Deserialize, Serialize};
use ssz::ssz_encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::Unsigned, BitVector, FixedVector};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub use self::committee_cache::CommitteeCache;
pub use beacon_state_types::*;

#[macro_use]
mod beacon_state_types;
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
    ShardOutOfBounds,
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
    NoCommitteeForShard,
    NoCommitteeForSlot,
    ZeroSlotsPerEpoch,
    PubkeyCacheInconsistent,
    PubkeyCacheIncomplete {
        cache_len: usize,
        registry_len: usize,
    },
    PreviousCommitteeCacheUninitialized,
    CurrentCommitteeCacheUninitialized,
    RelativeEpochError(RelativeEpochError),
    CommitteeCacheUninitialized(RelativeEpoch),
    SszTypesError(ssz_types::Error),
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

/// The state of the `BeaconChain` at some slot.
///
/// Spec v0.8.0
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
    CompareFields,
)]
#[serde(bound = "T: EthSpec")]
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
    pub block_roots: FixedVector<Hash256, T::SlotsPerHistoricalRoot>,
    #[compare_fields(as_slice)]
    pub state_roots: FixedVector<Hash256, T::SlotsPerHistoricalRoot>,
    pub historical_roots: VariableList<Hash256, T::HistoricalRootsLimit>,

    // Ethereum 1.0 chain data
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: VariableList<Eth1Data, T::SlotsPerEth1VotingPeriod>,
    pub eth1_deposit_index: u64,

    // Registry
    #[compare_fields(as_slice)]
    pub validators: VariableList<Validator, T::ValidatorRegistryLimit>,
    #[compare_fields(as_slice)]
    pub balances: VariableList<u64, T::ValidatorRegistryLimit>,

    // Shuffling
    pub start_shard: u64,
    pub randao_mixes: FixedVector<Hash256, T::EpochsPerHistoricalVector>,
    #[compare_fields(as_slice)]
    pub active_index_roots: FixedVector<Hash256, T::EpochsPerHistoricalVector>,
    #[compare_fields(as_slice)]
    pub compact_committees_roots: FixedVector<Hash256, T::EpochsPerHistoricalVector>,

    // Slashings
    pub slashings: FixedVector<u64, T::EpochsPerSlashingsVector>,

    // Attestations
    pub previous_epoch_attestations: VariableList<PendingAttestation<T>, T::MaxPendingAttestations>,
    pub current_epoch_attestations: VariableList<PendingAttestation<T>, T::MaxPendingAttestations>,

    // Crosslinks
    pub previous_crosslinks: FixedVector<Crosslink, T::ShardCount>,
    pub current_crosslinks: FixedVector<Crosslink, T::ShardCount>,

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
}

impl<T: EthSpec> BeaconState<T> {
    /// Create a new BeaconState suitable for genesis.
    ///
    /// Not a complete genesis state, see `initialize_beacon_state_from_eth1`.
    ///
    /// Spec v0.8.0
    pub fn new(genesis_time: u64, eth1_data: Eth1Data, spec: &ChainSpec) -> Self {
        BeaconState {
            // Versioning
            genesis_time,
            slot: spec.genesis_slot,
            fork: Fork::genesis(T::genesis_epoch()),

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

            // Shuffling
            start_shard: 0,
            randao_mixes: FixedVector::from_elem(Hash256::zero()),
            active_index_roots: FixedVector::from_elem(Hash256::zero()),
            compact_committees_roots: FixedVector::from_elem(Hash256::zero()),

            // Slashings
            slashings: FixedVector::from_elem(0),

            // Attestations
            previous_epoch_attestations: VariableList::empty(),
            current_epoch_attestations: VariableList::empty(),

            // Crosslinks
            previous_crosslinks: FixedVector::from_elem(Crosslink::default()),
            current_crosslinks: FixedVector::from_elem(Crosslink::default()),

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
        }
    }

    /// Returns the `tree_hash_root` of the state.
    ///
    /// Spec v0.8.1
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
    pub fn get_validator_index(&self, pubkey: &PublicKey) -> Result<Option<usize>, Error> {
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
    /// Spec v0.8.1
    pub fn current_epoch(&self) -> Epoch {
        self.slot.epoch(T::slots_per_epoch())
    }

    /// The epoch prior to `self.current_epoch()`.
    ///
    /// If the current epoch is the genesis epoch, the genesis_epoch is returned.
    ///
    /// Spec v0.8.1
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
    /// Spec v0.8.1
    pub fn next_epoch(&self) -> Epoch {
        self.current_epoch() + 1
    }

    pub fn get_committee_count(&self, relative_epoch: RelativeEpoch) -> Result<u64, Error> {
        let cache = self.cache(relative_epoch)?;

        Ok(cache.epoch_committee_count() as u64)
    }

    pub fn get_epoch_start_shard(&self, relative_epoch: RelativeEpoch) -> Result<u64, Error> {
        let cache = self.cache(relative_epoch)?;

        Ok(cache.epoch_start_shard())
    }

    /// Get the slot of an attestation.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.8.0
    pub fn get_attestation_data_slot(
        &self,
        attestation_data: &AttestationData,
    ) -> Result<Slot, Error> {
        let target_relative_epoch =
            RelativeEpoch::from_epoch(self.current_epoch(), attestation_data.target.epoch)?;

        let cc = self.get_crosslink_committee_for_shard(
            attestation_data.crosslink.shard,
            target_relative_epoch,
        )?;

        Ok(cc.slot)
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
        let cache = self.cache(relative_epoch)?;

        Ok(&cache.active_validator_indices())
    }

    /// Returns the active validator indices for the given epoch.
    ///
    /// Does not utilize the cache, performs a full iteration over the validator registry.
    ///
    /// Spec v0.8.1
    pub fn get_active_validator_indices(&self, epoch: Epoch) -> Vec<usize> {
        get_active_validator_indices(&self.validators, epoch)
    }

    /// Return the cached active validator indices at some epoch.
    ///
    /// Note: the indices are shuffled (i.e., not in ascending order).
    ///
    /// Returns an error if that epoch is not cached, or the cache is not initialized.
    pub fn get_shuffling(&self, relative_epoch: RelativeEpoch) -> Result<&[usize], Error> {
        let cache = self.cache(relative_epoch)?;

        Ok(cache.shuffling())
    }

    /// Returns the crosslink committees for some slot.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.8.1
    pub fn get_crosslink_committees_at_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<CrosslinkCommittee>, Error> {
        let relative_epoch = RelativeEpoch::from_slot(self.slot, slot, T::slots_per_epoch())?;
        let cache = self.cache(relative_epoch)?;

        cache
            .get_crosslink_committees_for_slot(slot)
            .ok_or_else(|| Error::NoCommitteeForSlot)
    }

    /// Returns the crosslink committees for some shard in some cached epoch.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.8.1
    pub fn get_crosslink_committee_for_shard(
        &self,
        shard: u64,
        relative_epoch: RelativeEpoch,
    ) -> Result<CrosslinkCommittee, Error> {
        let cache = self.cache(relative_epoch)?;

        let committee = cache
            .get_crosslink_committee_for_shard(shard)
            .ok_or_else(|| Error::NoCommitteeForShard)?;

        Ok(committee)
    }

    /// Returns the beacon proposer index for the `slot` in the given `relative_epoch`.
    ///
    /// Spec v0.8.1
    // NOTE: be sure to test this bad boy.
    pub fn get_beacon_proposer_index(
        &self,
        slot: Slot,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<usize, Error> {
        let cache = self.cache(relative_epoch)?;
        let epoch = relative_epoch.into_epoch(self.current_epoch());

        let first_committee = cache
            .first_committee_at_slot(slot)
            .ok_or_else(|| Error::SlotOutOfBounds)?;
        let seed = self.get_seed(epoch, spec)?;

        if first_committee.is_empty() {
            return Err(Error::InsufficientValidators);
        }

        let mut i = 0;
        Ok(loop {
            let candidate_index = first_committee[(epoch.as_usize() + i) % first_committee.len()];
            let random_byte = {
                let mut preimage = seed.as_bytes().to_vec();
                preimage.append(&mut int_to_bytes8((i / 32) as u64));
                let hash = hash(&preimage);
                hash[i % 32]
            };
            let effective_balance = self.validators[candidate_index].effective_balance;
            if (effective_balance * MAX_RANDOM_BYTE)
                >= (spec.max_effective_balance * u64::from(random_byte))
            {
                break candidate_index;
            }
            i += 1;
        })
    }

    /// Safely obtains the index for latest block roots, given some `slot`.
    ///
    /// Spec v0.8.1
    fn get_latest_block_roots_index(&self, slot: Slot) -> Result<usize, Error> {
        if (slot < self.slot) && (self.slot <= slot + self.block_roots.len() as u64) {
            Ok(slot.as_usize() % self.block_roots.len())
        } else {
            Err(BeaconStateError::SlotOutOfBounds)
        }
    }

    /// Return the block root at a recent `slot`.
    ///
    /// Spec v0.8.1
    pub fn get_block_root(&self, slot: Slot) -> Result<&Hash256, BeaconStateError> {
        let i = self.get_latest_block_roots_index(slot)?;
        Ok(&self.block_roots[i])
    }

    /// Return the block root at a recent `epoch`.
    ///
    /// Spec v0.8.1
    // NOTE: the spec calls this get_block_root
    pub fn get_block_root_at_epoch(&self, epoch: Epoch) -> Result<&Hash256, BeaconStateError> {
        self.get_block_root(epoch.start_slot(T::slots_per_epoch()))
    }

    /// Sets the block root for some given slot.
    ///
    /// Spec v0.8.1
    pub fn set_block_root(
        &mut self,
        slot: Slot,
        block_root: Hash256,
    ) -> Result<(), BeaconStateError> {
        let i = self.get_latest_block_roots_index(slot)?;
        self.block_roots[i] = block_root;
        Ok(())
    }

    /// Safely obtains the index for `randao_mixes`
    ///
    /// Spec v0.8.1
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
    /// Spec v0.8.0
    pub fn update_randao_mix(&mut self, epoch: Epoch, signature: &Signature) -> Result<(), Error> {
        let i = epoch.as_usize() % T::EpochsPerHistoricalVector::to_usize();

        let signature_hash = Hash256::from_slice(&hash(&ssz_encode(signature)));

        self.randao_mixes[i] = *self.get_randao_mix(epoch)? ^ signature_hash;

        Ok(())
    }

    /// Return the randao mix at a recent ``epoch``.
    ///
    /// Spec v0.8.1
    pub fn get_randao_mix(&self, epoch: Epoch) -> Result<&Hash256, Error> {
        let i = self.get_randao_mix_index(epoch, AllowNextEpoch::False)?;
        Ok(&self.randao_mixes[i])
    }

    /// Set the randao mix at a recent ``epoch``.
    ///
    /// Spec v0.8.1
    pub fn set_randao_mix(&mut self, epoch: Epoch, mix: Hash256) -> Result<(), Error> {
        let i = self.get_randao_mix_index(epoch, AllowNextEpoch::True)?;
        self.randao_mixes[i] = mix;
        Ok(())
    }

    /// Safely obtains the index for `active_index_roots`, given some `epoch`.
    ///
    /// If `allow_next_epoch` is `True`, then we allow an _extra_ one epoch of lookahead.
    ///
    /// Spec v0.8.1
    fn get_active_index_root_index(
        &self,
        epoch: Epoch,
        spec: &ChainSpec,
        allow_next_epoch: AllowNextEpoch,
    ) -> Result<usize, Error> {
        let current_epoch = self.current_epoch();

        let lookahead = spec.activation_exit_delay;
        let lookback = self.active_index_roots.len() as u64 - lookahead;
        let epoch_upper_bound = allow_next_epoch.upper_bound_of(current_epoch) + lookahead;

        if current_epoch < epoch + lookback && epoch <= epoch_upper_bound {
            Ok(epoch.as_usize() % self.active_index_roots.len())
        } else {
            Err(Error::EpochOutOfBounds)
        }
    }

    /// Return the `active_index_root` at a recent `epoch`.
    ///
    /// Spec v0.8.1
    pub fn get_active_index_root(&self, epoch: Epoch, spec: &ChainSpec) -> Result<Hash256, Error> {
        let i = self.get_active_index_root_index(epoch, spec, AllowNextEpoch::False)?;
        Ok(self.active_index_roots[i])
    }

    /// Set the `active_index_root` at a recent `epoch`.
    ///
    /// Spec v0.8.1
    pub fn set_active_index_root(
        &mut self,
        epoch: Epoch,
        index_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let i = self.get_active_index_root_index(epoch, spec, AllowNextEpoch::True)?;
        self.active_index_roots[i] = index_root;
        Ok(())
    }

    /// Replace `active_index_roots` with clones of `index_root`.
    ///
    /// Spec v0.8.0
    pub fn fill_active_index_roots_with(&mut self, index_root: Hash256) {
        self.active_index_roots = FixedVector::from_elem(index_root);
    }

    /// Safely obtains the index for `compact_committees_roots`, given some `epoch`.
    ///
    /// Spec v0.8.1
    fn get_compact_committee_root_index(
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

    /// Return the `compact_committee_root` at a recent `epoch`.
    ///
    /// Spec v0.8.1
    pub fn get_compact_committee_root(&self, epoch: Epoch) -> Result<Hash256, Error> {
        let i = self.get_compact_committee_root_index(epoch, AllowNextEpoch::False)?;
        Ok(self.compact_committees_roots[i])
    }

    /// Set the `compact_committee_root` at a recent `epoch`.
    ///
    /// Spec v0.8.1
    pub fn set_compact_committee_root(
        &mut self,
        epoch: Epoch,
        index_root: Hash256,
    ) -> Result<(), Error> {
        let i = self.get_compact_committee_root_index(epoch, AllowNextEpoch::True)?;
        self.compact_committees_roots[i] = index_root;
        Ok(())
    }

    /// Replace `compact_committees_roots` with clones of `committee_root`.
    ///
    /// Spec v0.8.0
    pub fn fill_compact_committees_roots_with(&mut self, committee_root: Hash256) {
        self.compact_committees_roots = FixedVector::from_elem(committee_root);
    }

    /// Safely obtains the index for latest state roots, given some `slot`.
    ///
    /// Spec v0.8.1
    fn get_latest_state_roots_index(&self, slot: Slot) -> Result<usize, Error> {
        if (slot < self.slot) && (self.slot <= slot + Slot::from(self.state_roots.len())) {
            Ok(slot.as_usize() % self.state_roots.len())
        } else {
            Err(BeaconStateError::SlotOutOfBounds)
        }
    }

    /// Gets the state root for some slot.
    ///
    /// Spec v0.8.1
    pub fn get_state_root(&self, slot: Slot) -> Result<&Hash256, Error> {
        let i = self.get_latest_state_roots_index(slot)?;
        Ok(&self.state_roots[i])
    }

    /// Gets the oldest (earliest slot) state root.
    ///
    /// Spec v0.8.1
    pub fn get_oldest_state_root(&self) -> Result<&Hash256, Error> {
        let i =
            self.get_latest_state_roots_index(self.slot - Slot::from(self.state_roots.len()))?;
        Ok(&self.state_roots[i])
    }

    /// Sets the latest state root for slot.
    ///
    /// Spec v0.8.1
    pub fn set_state_root(&mut self, slot: Slot, state_root: Hash256) -> Result<(), Error> {
        let i = self.get_latest_state_roots_index(slot)?;
        self.state_roots[i] = state_root;
        Ok(())
    }

    /// Safely obtain the index for `slashings`, given some `epoch`.
    ///
    /// Spec v0.8.1
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
    /// Spec v0.8.0
    pub fn get_all_slashings(&self) -> &[u64] {
        &self.slashings
    }

    /// Get the total slashed balances for some epoch.
    ///
    /// Spec v0.8.1
    pub fn get_slashings(&self, epoch: Epoch) -> Result<u64, Error> {
        let i = self.get_slashings_index(epoch, AllowNextEpoch::False)?;
        Ok(self.slashings[i])
    }

    /// Set the total slashed balances for some epoch.
    ///
    /// Spec v0.8.1
    pub fn set_slashings(&mut self, epoch: Epoch, value: u64) -> Result<(), Error> {
        let i = self.get_slashings_index(epoch, AllowNextEpoch::True)?;
        self.slashings[i] = value;
        Ok(())
    }

    /// Get the attestations from the current or previous epoch.
    ///
    /// Spec v0.8.1
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

    /// Get the current crosslink for a shard.
    ///
    /// Spec v0.8.1
    pub fn get_current_crosslink(&self, shard: u64) -> Result<&Crosslink, Error> {
        self.current_crosslinks
            .get(shard as usize)
            .ok_or(Error::ShardOutOfBounds)
    }

    /// Get the previous crosslink for a shard.
    ///
    /// Spec v0.8.1
    pub fn get_previous_crosslink(&self, shard: u64) -> Result<&Crosslink, Error> {
        self.previous_crosslinks
            .get(shard as usize)
            .ok_or(Error::ShardOutOfBounds)
    }

    /// Generate a seed for the given `epoch`.
    ///
    /// Spec v0.8.0
    pub fn get_seed(&self, epoch: Epoch, spec: &ChainSpec) -> Result<Hash256, Error> {
        // Bypass the safe getter for RANDAO so we can gracefully handle the scenario where `epoch
        // == 0`.
        let randao = {
            let i = epoch + T::EpochsPerHistoricalVector::to_u64() - spec.min_seed_lookahead - 1;
            self.randao_mixes[i.as_usize() % self.randao_mixes.len()]
        };
        let active_index_root = self.get_active_index_root(epoch, spec)?;
        let epoch_bytes = int_to_bytes32(epoch.as_u64());

        let mut preimage = [0; 32 * 3];
        preimage[0..32].copy_from_slice(&randao[..]);
        preimage[32..64].copy_from_slice(&active_index_root[..]);
        preimage[64..].copy_from_slice(&epoch_bytes);

        Ok(Hash256::from_slice(&hash(&preimage)))
    }

    /// Return the effective balance (also known as "balance at stake") for a validator with the given ``index``.
    ///
    /// Spec v0.8.1
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
    ///  Spec v0.8.1
    pub fn compute_activation_exit_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> Epoch {
        epoch + 1 + spec.activation_exit_delay
    }

    /// Return the churn limit for the current epoch (number of validators who can leave per epoch).
    ///
    /// Uses the epoch cache, and will error if it isn't initialized.
    ///
    /// Spec v0.8.1
    pub fn get_churn_limit(&self, spec: &ChainSpec) -> Result<u64, Error> {
        Ok(std::cmp::max(
            spec.min_per_epoch_churn_limit,
            self.cache(RelativeEpoch::Current)?.active_validator_count() as u64
                / spec.churn_limit_quotient,
        ))
    }

    /// Returns the `slot`, `shard` and `committee_index` for which a validator must produce an
    /// attestation.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.8.1
    pub fn get_attestation_duties(
        &self,
        validator_index: usize,
        relative_epoch: RelativeEpoch,
    ) -> Result<Option<AttestationDuty>, Error> {
        let cache = self.cache(relative_epoch)?;

        Ok(cache.get_attestation_duties(validator_index))
    }

    /// Return the combined effective balance of an array of validators.
    ///
    /// Spec v0.8.1
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
        self.update_tree_hash_cache()?;
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
        let i = Self::cache_index(relative_epoch);

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

        self.committee_caches[Self::cache_index(relative_epoch)] =
            CommitteeCache::initialized(&self, epoch, spec)?;
        Ok(())
    }

    /// Advances the cache for this state into the next epoch.
    ///
    /// This should be used if the `slot` of this state is advanced beyond an epoch boundary.
    ///
    /// Note: whilst this function will preserve already-built caches, it will not build any.
    pub fn advance_caches(&mut self) {
        let next = Self::cache_index(RelativeEpoch::Previous);
        let current = Self::cache_index(RelativeEpoch::Current);

        let caches = &mut self.committee_caches[..];
        caches.rotate_left(1);
        caches[next] = CommitteeCache::default();
        caches[current] = CommitteeCache::default();
    }

    fn cache_index(relative_epoch: RelativeEpoch) -> usize {
        match relative_epoch {
            RelativeEpoch::Previous => 0,
            RelativeEpoch::Current => 1,
            RelativeEpoch::Next => 2,
        }
    }

    /// Returns the cache for some `RelativeEpoch`. Returns an error if the cache has not been
    /// initialized.
    fn cache(&self, relative_epoch: RelativeEpoch) -> Result<&CommitteeCache, Error> {
        let cache = &self.committee_caches[Self::cache_index(relative_epoch)];

        if cache.is_initialized_at(relative_epoch.into_epoch(self.current_epoch())) {
            Ok(cache)
        } else {
            Err(Error::CommitteeCacheUninitialized(relative_epoch))
        }
    }

    /// Drops the cache, leaving it in an uninitialized state.
    fn drop_committee_cache(&mut self, relative_epoch: RelativeEpoch) {
        self.committee_caches[Self::cache_index(relative_epoch)] = CommitteeCache::default();
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
    ///
    /// ## Note
    ///
    /// Cache not currently implemented, just performs a full tree hash.
    pub fn update_tree_hash_cache(&mut self) -> Result<Hash256, Error> {
        // TODO(#440): re-enable cached tree hash
        Ok(Hash256::from_slice(&self.tree_hash_root()))
    }

    /// Returns the tree hash root determined by the last execution of `self.update_tree_hash_cache(..)`.
    ///
    /// Note: does _not_ update the cache and may return an outdated root.
    ///
    /// Returns an error if the cache is not initialized or if an error is encountered during the
    /// cache update.
    ///
    /// ## Note
    ///
    /// Cache not currently implemented, just performs a full tree hash.
    pub fn cached_tree_hash_root(&self) -> Result<Hash256, Error> {
        // TODO(#440): re-enable cached tree hash
        Ok(Hash256::from_slice(&self.tree_hash_root()))
    }

    /// Completely drops the tree hash cache, replacing it with a new, empty cache.
    ///
    /// ## Note
    ///
    /// Cache not currently implemented, is a no-op.
    pub fn drop_tree_hash_cache(&mut self) {
        // TODO(#440): re-enable cached tree hash
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
