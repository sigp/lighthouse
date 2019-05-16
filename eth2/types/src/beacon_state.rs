use self::epoch_cache::{get_active_validator_indices, EpochCache, Error as EpochCacheError};
use self::exit_cache::ExitCache;
use crate::test_utils::TestRandom;
use crate::*;
use cached_tree_hash::{Error as TreeHashCacheError, TreeHashCache};
use hashing::hash;
use int_to_bytes::int_to_bytes32;
use pubkey_cache::PubkeyCache;

use fixed_len_vec::{typenum::Unsigned, FixedLenVec};
use serde_derive::{Deserialize, Serialize};
use ssz::ssz_encode;
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::{CachedTreeHash, TreeHash};

pub use beacon_state_types::*;

mod beacon_state_types;
mod epoch_cache;
mod exit_cache;
mod pubkey_cache;
mod tests;

pub const CACHED_EPOCHS: usize = 3;

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
    PreviousEpochCacheUninitialized,
    CurrentEpochCacheUnintialized,
    EpochCacheUnintialized(RelativeEpoch),
    EpochCacheError(EpochCacheError),
    TreeHashCacheError(TreeHashCacheError),
}

/// The state of the `BeaconChain` at some slot.
///
/// Spec v0.6.1
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
pub struct BeaconState<T>
where
    T: EthSpec,
{
    // Misc
    pub slot: Slot,
    pub genesis_time: u64,
    pub fork: Fork,

    // Validator registry
    pub validator_registry: Vec<Validator>,
    pub balances: Vec<u64>,

    // Randomness and committees
    pub latest_randao_mixes: FixedLenVec<Hash256, T::LatestRandaoMixesLength>,
    pub latest_start_shard: u64,

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
    pub current_crosslinks: FixedLenVec<Crosslink, T::ShardCount>,
    pub previous_crosslinks: FixedLenVec<Crosslink, T::ShardCount>,
    pub latest_block_roots: FixedLenVec<Hash256, T::SlotsPerHistoricalRoot>,
    latest_state_roots: FixedLenVec<Hash256, T::SlotsPerHistoricalRoot>,
    latest_active_index_roots: FixedLenVec<Hash256, T::LatestActiveIndexRootsLength>,
    latest_slashed_balances: FixedLenVec<u64, T::LatestSlashedExitLength>,
    pub latest_block_header: BeaconBlockHeader,
    pub historical_roots: Vec<Hash256>,

    // Ethereum 1.0 chain data
    pub latest_eth1_data: Eth1Data,
    pub eth1_data_votes: Vec<Eth1Data>,
    pub deposit_index: u64,

    // Caching (not in the spec)
    #[serde(default)]
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    pub epoch_caches: [EpochCache; CACHED_EPOCHS],
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
    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    pub exit_cache: ExitCache,
}

impl<T: EthSpec> BeaconState<T> {
    /// Produce the first state of the Beacon Chain.
    ///
    /// This does not fully build a genesis beacon state, it omits processing of initial validator
    /// deposits. To obtain a full genesis beacon state, use the `BeaconStateBuilder`.
    ///
    /// Spec v0.6.1
    pub fn genesis(
        genesis_time: u64,
        latest_eth1_data: Eth1Data,
        spec: &ChainSpec,
    ) -> BeaconState<T> {
        let initial_crosslink = Crosslink {
            epoch: spec.genesis_epoch,
            previous_crosslink_root: spec.zero_hash,
            crosslink_data_root: spec.zero_hash,
        };

        BeaconState {
            // Misc
            slot: spec.genesis_slot,
            genesis_time,
            fork: Fork::genesis(spec),

            // Validator registry
            validator_registry: vec![], // Set later in the function.
            balances: vec![],           // Set later in the function.

            // Randomness and committees
            latest_randao_mixes: FixedLenVec::from(vec![
                spec.zero_hash;
                T::LatestRandaoMixesLength::to_usize()
            ]),
            latest_start_shard: 0,

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
            current_crosslinks: vec![initial_crosslink.clone(); T::ShardCount::to_usize()].into(),
            previous_crosslinks: vec![initial_crosslink; T::ShardCount::to_usize()].into(),
            latest_block_roots: vec![spec.zero_hash; T::SlotsPerHistoricalRoot::to_usize()].into(),
            latest_state_roots: vec![spec.zero_hash; T::SlotsPerHistoricalRoot::to_usize()].into(),
            latest_active_index_roots: vec![
                spec.zero_hash;
                T::LatestActiveIndexRootsLength::to_usize()
            ]
            .into(),
            latest_slashed_balances: vec![0; T::LatestSlashedExitLength::to_usize()].into(),
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
            epoch_caches: [
                EpochCache::default(),
                EpochCache::default(),
                EpochCache::default(),
            ],
            pubkey_cache: PubkeyCache::default(),
            tree_hash_cache: TreeHashCache::default(),
            exit_cache: ExitCache::default(),
        }
    }

    /// Returns the `tree_hash_root` of the state.
    ///
    /// Spec v0.6.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.tree_hash_root()[..])
    }

    pub fn historical_batch(&self) -> HistoricalBatch<T> {
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
    /// Spec v0.6.1
    pub fn current_epoch(&self) -> Epoch {
        self.slot.epoch(T::slots_per_epoch())
    }

    /// The epoch prior to `self.current_epoch()`.
    ///
    /// If the current epoch is the genesis epoch, the genesis_epoch is returned.
    ///
    /// Spec v0.6.1
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
    /// Spec v0.6.1
    pub fn next_epoch(&self) -> Epoch {
        self.current_epoch() + 1
    }

    /// Return the number of committees at ``epoch``.
    ///
    /// Spec v0.6.1
    pub fn get_epoch_committee_count(&self, epoch: Epoch, spec: &ChainSpec) -> u64 {
        let active_validator_indices = self.get_active_validator_indices(epoch);
        spec.get_epoch_committee_count(active_validator_indices.len())
    }

    /// Return the number of shards to increment `state.latest_start_shard` during `epoch`.
    ///
    /// Spec v0.6.1
    pub fn get_shard_delta(&self, epoch: Epoch, spec: &ChainSpec) -> u64 {
        std::cmp::min(
            self.get_epoch_committee_count(epoch, spec),
            T::ShardCount::to_u64() - T::ShardCount::to_u64() / spec.slots_per_epoch,
        )
    }

    /// Return the start shard for an epoch less than or equal to the next epoch.
    ///
    /// Spec v0.6.1
    pub fn get_epoch_start_shard(&self, epoch: Epoch, spec: &ChainSpec) -> Result<u64, Error> {
        if epoch > self.current_epoch() + 1 {
            return Err(Error::EpochOutOfBounds);
        }
        let shard_count = T::ShardCount::to_u64();
        let mut check_epoch = self.current_epoch() + 1;
        let mut shard = (self.latest_start_shard
            + self.get_shard_delta(self.current_epoch(), spec))
            % shard_count;
        while check_epoch > epoch {
            check_epoch -= 1;
            shard = (shard + shard_count - self.get_shard_delta(check_epoch, spec)) % shard_count;
        }
        Ok(shard)
    }

    /// Get the slot of an attestation.
    ///
    /// Spec v0.6.1
    pub fn get_attestation_slot(
        &self,
        attestation_data: &AttestationData,
        spec: &ChainSpec,
    ) -> Result<Slot, Error> {
        let epoch = attestation_data.target_epoch;
        let committee_count = self.get_epoch_committee_count(epoch, spec);
        let offset = (attestation_data.shard + spec.shard_count
            - self.get_epoch_start_shard(epoch, spec)?)
            % spec.shard_count;
        Ok(epoch.start_slot(spec.slots_per_epoch)
            + offset / (committee_count / spec.slots_per_epoch))
    }

    // FIXME(sproul): get_cached_current_active_validator_indices
    /*
    pub fn get_cached_active_validator_indices(
        &self,
        spec: &ChainSpec,
    ) -> Result<&[usize], Error> {
        let cache = self.cache(relative_epoch, spec)?;

        Ok(&cache.active_validator_indices)
    }
    */

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
        unimplemented!("FIXME(sproul)")
    }

    /// Return the crosslink committeee for `shard` in `epoch`.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.6.1
    pub fn get_crosslink_committee(
        &self,
        epoch: Epoch,
        shard: u64,
        spec: &ChainSpec,
    ) -> Result<&CrosslinkCommittee, Error> {
        drop((epoch, shard, spec));
        unimplemented!()
    }

    /// Returns the beacon proposer index for the `slot`.
    ///
    /// If the state does not contain an index for a beacon proposer at the requested `slot`, then `None` is returned.
    ///
    /// Spec v0.5.1
    pub fn get_beacon_proposer_index(&self, spec: &ChainSpec) -> Result<usize, Error> {
        unimplemented!("FIXME(sproul)")
        /*
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
        */
    }

    /// Safely obtains the index for latest block roots, given some `slot`.
    ///
    /// Spec v0.5.1
    fn get_latest_block_roots_index(&self, slot: Slot) -> Result<usize, Error> {
        if (slot < self.slot) && (self.slot <= slot + self.latest_block_roots.len() as u64) {
            Ok(slot.as_usize() % self.latest_block_roots.len())
        } else {
            Err(BeaconStateError::SlotOutOfBounds)
        }
    }

    /// Return the block root at a recent `slot`.
    ///
    /// Spec v0.5.1
    pub fn get_block_root(&self, slot: Slot) -> Result<&Hash256, BeaconStateError> {
        let i = self.get_latest_block_roots_index(slot)?;
        Ok(&self.latest_block_roots[i])
    }

    /// Return the block root at a recent `slot`.
    ///
    /// Spec v0.6.0
    // FIXME(sproul): name swap with get_block_root
    pub fn get_block_root_at_epoch(
        &self,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<&Hash256, BeaconStateError> {
        self.get_block_root(epoch.start_slot(spec.slots_per_epoch))
    }

    /// Sets the block root for some given slot.
    ///
    /// Spec v0.5.1
    pub fn set_block_root(
        &mut self,
        slot: Slot,
        block_root: Hash256,
    ) -> Result<(), BeaconStateError> {
        let i = self.get_latest_block_roots_index(slot)?;
        self.latest_block_roots[i] = block_root;
        Ok(())
    }

    /// Safely obtains the index for `latest_randao_mixes`
    ///
    /// Spec v0.5.1
    fn get_randao_mix_index(&self, epoch: Epoch) -> Result<usize, Error> {
        let current_epoch = self.current_epoch();
        let len = T::LatestRandaoMixesLength::to_u64();

        if (current_epoch - len < epoch) & (epoch <= current_epoch) {
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
    /// Spec v0.5.1
    pub fn update_randao_mix(
        &mut self,
        epoch: Epoch,
        signature: &Signature,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let i = epoch.as_usize() % T::LatestRandaoMixesLength::to_usize();

        let signature_hash = Hash256::from_slice(&hash(&ssz_encode(signature)));

        self.latest_randao_mixes[i] = *self.get_randao_mix(epoch)? ^ signature_hash;

        Ok(())
    }

    /// Return the randao mix at a recent ``epoch``.
    ///
    /// Spec v0.5.1
    pub fn get_randao_mix(&self, epoch: Epoch) -> Result<&Hash256, Error> {
        let i = self.get_randao_mix_index(epoch)?;
        Ok(&self.latest_randao_mixes[i])
    }

    /// Set the randao mix at a recent ``epoch``.
    ///
    /// Spec v0.5.1
    pub fn set_randao_mix(&mut self, epoch: Epoch, mix: Hash256) -> Result<(), Error> {
        let i = self.get_randao_mix_index(epoch)?;
        self.latest_randao_mixes[i] = mix;
        Ok(())
    }

    /// Safely obtains the index for `latest_active_index_roots`, given some `epoch`.
    ///
    /// Spec v0.6.1
    fn get_active_index_root_index(&self, epoch: Epoch, spec: &ChainSpec) -> Result<usize, Error> {
        let current_epoch = self.current_epoch();

        if current_epoch - self.latest_active_index_roots.len() as u64 + spec.activation_exit_delay
            < epoch
            && epoch <= current_epoch + spec.activation_exit_delay
        {
            Ok(epoch.as_usize() % self.latest_active_index_roots.len())
        } else {
            Err(Error::EpochOutOfBounds)
        }
    }

    /// Return the `active_index_root` at a recent `epoch`.
    ///
    /// Spec v0.6.1
    pub fn get_active_index_root(&self, epoch: Epoch, spec: &ChainSpec) -> Result<Hash256, Error> {
        let i = self.get_active_index_root_index(epoch, spec)?;
        Ok(self.latest_active_index_roots[i])
    }

    /// Set the `active_index_root` at a recent `epoch`.
    ///
    /// Spec v0.6.1
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
    pub fn fill_active_index_roots_with(&mut self, index_root: Hash256) {
        self.latest_active_index_roots =
            vec![index_root; self.latest_active_index_roots.len() as usize].into()
    }

    /// Safely obtains the index for latest state roots, given some `slot`.
    ///
    /// Spec v0.5.1
    fn get_latest_state_roots_index(&self, slot: Slot) -> Result<usize, Error> {
        if (slot < self.slot) && (self.slot <= slot + self.latest_state_roots.len() as u64) {
            Ok(slot.as_usize() % self.latest_state_roots.len())
        } else {
            Err(BeaconStateError::SlotOutOfBounds)
        }
    }

    /// Gets the state root for some slot.
    ///
    /// Spec v0.5.1
    pub fn get_state_root(&mut self, slot: Slot) -> Result<&Hash256, Error> {
        let i = self.get_latest_state_roots_index(slot)?;
        Ok(&self.latest_state_roots[i])
    }

    /// Sets the latest state root for slot.
    ///
    /// Spec v0.5.1
    pub fn set_state_root(&mut self, slot: Slot, state_root: Hash256) -> Result<(), Error> {
        let i = self.get_latest_state_roots_index(slot)?;
        self.latest_state_roots[i] = state_root;
        Ok(())
    }

    /// Safely obtains the index for `latest_slashed_balances`, given some `epoch`.
    ///
    /// Spec v0.6.1
    fn get_slashed_balance_index(&self, epoch: Epoch) -> Result<usize, Error> {
        let i = epoch.as_usize() % self.latest_slashed_balances.len();

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
    /// Spec v0.6.1
    pub fn get_slashed_balance(&self, epoch: Epoch) -> Result<u64, Error> {
        let i = self.get_slashed_balance_index(epoch)?;
        Ok(self.latest_slashed_balances[i])
    }

    /// Sets the total slashed balances for some epoch.
    ///
    /// Spec v0.6.1
    pub fn set_slashed_balance(&mut self, epoch: Epoch, balance: u64) -> Result<(), Error> {
        let i = self.get_slashed_balance_index(epoch)?;
        self.latest_slashed_balances[i] = balance;
        Ok(())
    }

    /// Get the attestations from the current or previous epoch.
    ///
    /// Spec v0.6.0
    pub fn get_matching_source_attestations(
        &self,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<&[PendingAttestation], Error> {
        if epoch == self.current_epoch() {
            Ok(&self.current_epoch_attestations)
        } else if epoch == self.previous_epoch() {
            Ok(&self.previous_epoch_attestations)
        } else {
            Err(Error::EpochOutOfBounds)
        }
    }

    /// Transform an attestation into the crosslink that it reinforces.
    ///
    /// Spec v0.6.1
    pub fn get_crosslink_from_attestation_data(
        &self,
        data: &AttestationData,
        spec: &ChainSpec,
    ) -> Crosslink {
        Crosslink {
            epoch: std::cmp::min(
                data.target_epoch,
                self.current_crosslinks[data.shard as usize].epoch + spec.max_crosslink_epochs,
            ),
            previous_crosslink_root: data.previous_crosslink_root,
            crosslink_data_root: data.crosslink_data_root,
        }
    }

    /// Generate a seed for the given `epoch`.
    ///
    /// Spec v0.5.1
    pub fn generate_seed(&self, epoch: Epoch, spec: &ChainSpec) -> Result<Hash256, Error> {
        let mut input = self
            .get_randao_mix(epoch - spec.min_seed_lookahead)?
            .as_bytes()
            .to_vec();

        input.append(&mut self.get_active_index_root(epoch, spec)?.as_bytes().to_vec());

        input.append(&mut int_to_bytes32(epoch.as_u64()));

        Ok(Hash256::from_slice(&hash(&input[..])[..]))
    }

    /// Return the effective balance (also known as "balance at stake") for a validator with the given ``index``.
    ///
    /// Spec v0.6.0
    pub fn get_effective_balance(
        &self,
        validator_index: usize,
        _spec: &ChainSpec,
    ) -> Result<u64, Error> {
        self.validator_registry
            .get(validator_index)
            .map(|v| v.effective_balance)
            .ok_or_else(|| Error::UnknownValidator)
    }

    ///  Return the epoch at which an activation or exit triggered in ``epoch`` takes effect.
    ///
    ///  Spec v0.5.1
    pub fn get_delayed_activation_exit_epoch(&self, epoch: Epoch, spec: &ChainSpec) -> Epoch {
        epoch + 1 + spec.activation_exit_delay
    }

    /// Return the churn limit for the current epoch (number of validators who can leave per epoch).
    ///
    /// Uses the epoch cache, and will error if it isn't initialized.
    ///
    /// Spec v0.6.1
    pub fn get_churn_limit(&self, spec: &ChainSpec) -> Result<u64, Error> {
        Ok(std::cmp::max(
            spec.min_per_epoch_churn_limit,
            self.cache(self.current_epoch(), spec)?
                .active_validator_indices
                .len() as u64
                / spec.churn_limit_quotient,
        ))
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
        let cache = self.cache(self.current_epoch(), spec)?;

        Ok(cache
            .attestation_duties
            .get(validator_index)
            .ok_or_else(|| Error::UnknownValidator)?)
    }

    /// Return the combined effective balance of an array of validators.
    ///
    /// Spec v0.6.0
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
        self.build_epoch_cache(RelativeEpoch::Next, spec)?;
        self.update_pubkey_cache()?;
        self.update_tree_hash_cache()?;
        self.exit_cache
            .build_from_registry(&self.validator_registry, spec);

        Ok(())
    }

    /// Build an epoch cache, unless it is has already been built.
    pub fn build_epoch_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let i = Self::cache_index(relative_epoch);

        if self.epoch_caches[i].is_initialized_at(self.previous_epoch()) {
            Ok(())
        } else {
            self.force_build_epoch_cache(relative_epoch, spec)
        }
    }

    /// Always builds the previous epoch cache, even if it is already initialized.
    pub fn force_build_epoch_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let epoch = relative_epoch.into_epoch(self.current_epoch());

        self.epoch_caches[Self::cache_index(relative_epoch)] = EpochCache::initialized(
            &self,
            epoch,
            self.generate_seed(epoch, spec)?,
            self.get_epoch_start_shard(epoch, spec)?,
            spec,
        )?;
        Ok(())
    }

    /// Advances the cache for this state into the next epoch.
    ///
    /// This should be used if the `slot` of this state is advanced beyond an epoch boundary.
    ///
    /// Note: whilst this function will preserve already-built caches, it will not build any.
    pub fn advance_caches(&mut self, spec: &ChainSpec) {
        let previous = Self::cache_index(RelativeEpoch::Previous);
        let current = Self::cache_index(RelativeEpoch::Previous);
        let next = Self::cache_index(RelativeEpoch::Previous);

        let caches = &mut self.epoch_caches[..];
        caches.rotate_left(1);
        caches[next] = EpochCache::default();
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
    fn cache(&self, epoch: Epoch, spec: &ChainSpec) -> Result<&EpochCache, Error> {
        let relative_epoch = RelativeEpoch::from_epoch(self.current_epoch(), epoch)
            .map_err(|e| Error::EpochOutOfBounds)?;

        let cache = &self.epoch_caches[Self::cache_index(relative_epoch)];

        if cache.is_initialized_at(epoch) {
            Ok(cache)
        } else {
            Err(Error::EpochCacheUnintialized(relative_epoch))
        }
    }

    // FIXME(sproul): drop_previous/current_epoch_cache

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
            self.tree_hash_cache = TreeHashCache::new(self)?;
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
            .tree_hash_root()
            .and_then(|b| Ok(Hash256::from_slice(b)))
            .map_err(Into::into)
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
