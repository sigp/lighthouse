use self::committee_cache::get_active_validator_indices;
use self::exit_cache::ExitCache;
use crate::test_utils::TestRandom;
use crate::*;
use compare_fields::CompareFields;
use compare_fields_derive::CompareFields;
use derivative::Derivative;
use eth2_hashing::hash;
use int_to_bytes::{int_to_bytes4, int_to_bytes8};
use pubkey_cache::PubkeyCache;
use safe_arith::{ArithError, SafeArith};
use serde_derive::{Deserialize, Serialize};
use ssz::{ssz_encode, Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::Unsigned, BitVector, FixedVector};
use std::convert::TryInto;
use std::{fmt, mem, sync::Arc};
use superstruct::superstruct;
use swap_or_not_shuffle::compute_shuffled_index;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub use self::committee_cache::{
    compute_committee_index_in_epoch, compute_committee_range_in_epoch, epoch_committee_count,
    CommitteeCache,
};
pub use clone_config::CloneConfig;
pub use eth_spec::*;
pub use iter::BlockRootsIter;
pub use tree_hash_cache::BeaconTreeHashCache;

#[macro_use]
mod committee_cache;
mod clone_config;
mod exit_cache;
mod iter;
mod pubkey_cache;
mod tests;
mod tree_hash_cache;

pub const CACHED_EPOCHS: usize = 3;
const MAX_RANDOM_BYTE: u64 = (1 << 8) - 1;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// A state for a different hard-fork was required -- a severe logic error.
    IncorrectStateVariant,
    EpochOutOfBounds,
    SlotOutOfBounds,
    UnknownValidator(usize),
    UnableToDetermineProducer,
    InvalidBitfield,
    ValidatorIsWithdrawable,
    ValidatorIsInactive {
        val_index: usize,
    },
    UnableToShuffle,
    ShuffleIndexOutOfBounds(usize),
    IsAggregatorOutOfBounds,
    BlockRootsOutOfBounds(usize),
    StateRootsOutOfBounds(usize),
    SlashingsOutOfBounds(usize),
    BalancesOutOfBounds(usize),
    RandaoMixesOutOfBounds(usize),
    CommitteeCachesOutOfBounds(usize),
    ParticipationOutOfBounds(usize),
    InactivityScoresOutOfBounds(usize),
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
    TotalActiveBalanceCacheUninitialized,
    TotalActiveBalanceCacheInconsistent {
        initialized_epoch: Epoch,
        current_epoch: Epoch,
    },
    RelativeEpochError(RelativeEpochError),
    ExitCacheUninitialized,
    CommitteeCacheUninitialized(Option<RelativeEpoch>),
    SyncCommitteeCacheUninitialized,
    BlsError(bls::Error),
    SszTypesError(ssz_types::Error),
    TreeHashCacheNotInitialized,
    NonLinearTreeHashCacheHistory,
    TreeHashCacheSkippedSlot {
        cache: Slot,
        state: Slot,
    },
    TreeHashError(tree_hash::Error),
    CachedTreeHashError(cached_tree_hash::Error),
    InvalidValidatorPubkey(ssz::DecodeError),
    ValidatorRegistryShrunk,
    TreeHashCacheInconsistent,
    InvalidDepositState {
        deposit_count: u64,
        deposit_index: u64,
    },
    /// Attestation slipped through block processing with a non-matching source.
    IncorrectAttestationSource,
    /// An arithmetic operation occurred which would have overflowed or divided by 0.
    ///
    /// This represents a serious bug in either the spec or Lighthouse!
    ArithError(ArithError),
    MissingBeaconBlock(SignedBeaconBlockHash),
    MissingBeaconState(BeaconStateHash),
    SyncCommitteeNotKnown {
        current_epoch: Epoch,
        epoch: Epoch,
    },
}

/// Control whether an epoch-indexed field can be indexed at the next epoch or not.
#[derive(Debug, PartialEq, Clone, Copy)]
enum AllowNextEpoch {
    True,
    False,
}

impl AllowNextEpoch {
    fn upper_bound_of(self, current_epoch: Epoch) -> Result<Epoch, Error> {
        match self {
            AllowNextEpoch::True => Ok(current_epoch.safe_add(1)?),
            AllowNextEpoch::False => Ok(current_epoch),
        }
    }
}

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct BeaconStateHash(Hash256);

impl fmt::Debug for BeaconStateHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BeaconStateHash({:?})", self.0)
    }
}

impl fmt::Display for BeaconStateHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Hash256> for BeaconStateHash {
    fn from(hash: Hash256) -> BeaconStateHash {
        BeaconStateHash(hash)
    }
}

impl From<BeaconStateHash> for Hash256 {
    fn from(beacon_state_hash: BeaconStateHash) -> Hash256 {
        beacon_state_hash.0
    }
}

/// The state of the `BeaconChain` at some slot.
#[superstruct(
    variants(Base, Altair),
    variant_attributes(
        derive(
            Derivative,
            Debug,
            PartialEq,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            TestRandom,
            CompareFields,
        ),
        serde(bound = "T: EthSpec", deny_unknown_fields),
        derivative(Clone),
        cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))
    ),
    cast_error(ty = "Error", expr = "Error::IncorrectStateVariant"),
    partial_getter_error(ty = "Error", expr = "Error::IncorrectStateVariant")
)]
#[derive(Debug, PartialEq, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct BeaconState<T>
where
    T: EthSpec,
{
    // Versioning
    #[superstruct(getter(copy))]
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub genesis_time: u64,
    #[superstruct(getter(copy))]
    pub genesis_validators_root: Hash256,
    #[superstruct(getter(copy))]
    pub slot: Slot,
    #[superstruct(getter(copy))]
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
    #[superstruct(getter(copy))]
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub eth1_deposit_index: u64,

    // Registry
    #[compare_fields(as_slice)]
    pub validators: VariableList<Validator, T::ValidatorRegistryLimit>,
    #[compare_fields(as_slice)]
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    pub balances: VariableList<u64, T::ValidatorRegistryLimit>,

    // Randomness
    pub randao_mixes: FixedVector<Hash256, T::EpochsPerHistoricalVector>,

    // Slashings
    #[serde(with = "ssz_types::serde_utils::quoted_u64_fixed_vec")]
    pub slashings: FixedVector<u64, T::EpochsPerSlashingsVector>,

    // Attestations (genesis fork only)
    #[superstruct(only(Base))]
    pub previous_epoch_attestations: VariableList<PendingAttestation<T>, T::MaxPendingAttestations>,
    #[superstruct(only(Base))]
    pub current_epoch_attestations: VariableList<PendingAttestation<T>, T::MaxPendingAttestations>,

    // Participation (Altair and later)
    #[superstruct(only(Altair))]
    pub previous_epoch_participation: VariableList<ParticipationFlags, T::ValidatorRegistryLimit>,
    #[superstruct(only(Altair))]
    pub current_epoch_participation: VariableList<ParticipationFlags, T::ValidatorRegistryLimit>,

    // Finality
    #[test_random(default)]
    pub justification_bits: BitVector<T::JustificationBitsLength>,
    #[superstruct(getter(copy))]
    pub previous_justified_checkpoint: Checkpoint,
    #[superstruct(getter(copy))]
    pub current_justified_checkpoint: Checkpoint,
    #[superstruct(getter(copy))]
    pub finalized_checkpoint: Checkpoint,

    // Inactivity
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    #[superstruct(only(Altair))]
    pub inactivity_scores: VariableList<u64, T::ValidatorRegistryLimit>,

    // Light-client sync committees
    #[superstruct(only(Altair))]
    pub current_sync_committee: Arc<SyncCommittee<T>>,
    #[superstruct(only(Altair))]
    pub next_sync_committee: Arc<SyncCommittee<T>>,

    // Caching (not in the spec)
    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    #[derivative(Clone(clone_with = "clone_default"))]
    pub total_active_balance: Option<(Epoch, u64)>,
    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    #[derivative(Clone(clone_with = "clone_default"))]
    pub committee_caches: [CommitteeCache; CACHED_EPOCHS],
    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    #[derivative(Clone(clone_with = "clone_default"))]
    pub pubkey_cache: PubkeyCache,
    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    #[derivative(Clone(clone_with = "clone_default"))]
    pub exit_cache: ExitCache,
    #[serde(skip_serializing, skip_deserializing)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    #[test_random(default)]
    #[derivative(Clone(clone_with = "clone_default"))]
    pub tree_hash_cache: BeaconTreeHashCache<T>,
}

impl<T: EthSpec> Clone for BeaconState<T> {
    fn clone(&self) -> Self {
        self.clone_with(CloneConfig::all())
    }
}

impl<T: EthSpec> BeaconState<T> {
    /// Create a new BeaconState suitable for genesis.
    ///
    /// Not a complete genesis state, see `initialize_beacon_state_from_eth1`.
    pub fn new(genesis_time: u64, eth1_data: Eth1Data, spec: &ChainSpec) -> Self {
        BeaconState::Base(BeaconStateBase {
            // Versioning
            genesis_time,
            genesis_validators_root: Hash256::zero(), // Set later.
            slot: spec.genesis_slot,
            fork: Fork {
                previous_version: spec.genesis_fork_version,
                current_version: spec.genesis_fork_version,
                epoch: T::genesis_epoch(),
            },

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
            total_active_balance: None,
            committee_caches: [
                CommitteeCache::default(),
                CommitteeCache::default(),
                CommitteeCache::default(),
            ],
            pubkey_cache: PubkeyCache::default(),
            exit_cache: ExitCache::default(),
            tree_hash_cache: <_>::default(),
        })
    }

    /// Returns the name of the fork pertaining to `self`.
    ///
    /// Will return an `Err` if `self` has been instantiated to a variant conflicting with the fork
    /// dictated by `self.slot()`.
    pub fn fork_name(&self, spec: &ChainSpec) -> Result<ForkName, InconsistentFork> {
        let fork_at_slot = spec.fork_name_at_epoch(self.current_epoch());
        let object_fork = match self {
            BeaconState::Base { .. } => ForkName::Base,
            BeaconState::Altair { .. } => ForkName::Altair,
        };

        if fork_at_slot == object_fork {
            Ok(object_fork)
        } else {
            Err(InconsistentFork {
                fork_at_slot,
                object_fork,
            })
        }
    }

    /// Specialised deserialisation method that uses the `ChainSpec` as context.
    #[allow(clippy::integer_arithmetic)]
    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        // Slot is after genesis_time (u64) and genesis_validators_root (Hash256).
        let slot_start = <u64 as Decode>::ssz_fixed_len() + <Hash256 as Decode>::ssz_fixed_len();
        let slot_end = slot_start + <Slot as Decode>::ssz_fixed_len();

        let slot_bytes = bytes
            .get(slot_start..slot_end)
            .ok_or(DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: slot_end,
            })?;

        let slot = Slot::from_ssz_bytes(slot_bytes)?;
        let epoch = slot.epoch(T::slots_per_epoch());

        if spec
            .altair_fork_epoch
            .map_or(true, |altair_epoch| epoch < altair_epoch)
        {
            BeaconStateBase::from_ssz_bytes(bytes).map(Self::Base)
        } else {
            BeaconStateAltair::from_ssz_bytes(bytes).map(Self::Altair)
        }
    }

    /// Returns the `tree_hash_root` of the state.
    ///
    /// Spec v0.12.1
    pub fn canonical_root(&self) -> Hash256 {
        Hash256::from_slice(&self.tree_hash_root()[..])
    }

    pub fn historical_batch(&self) -> HistoricalBatch<T> {
        HistoricalBatch {
            block_roots: self.block_roots().clone(),
            state_roots: self.state_roots().clone(),
        }
    }

    /// This method ensures the state's pubkey cache is fully up-to-date before checking if the validator
    /// exists in the registry. If a validator pubkey exists in the validator registry, returns `Some(i)`,
    /// otherwise returns `None`.
    pub fn get_validator_index(&mut self, pubkey: &PublicKeyBytes) -> Result<Option<usize>, Error> {
        self.update_pubkey_cache()?;
        Ok(self.pubkey_cache().get(pubkey))
    }

    /// The epoch corresponding to `self.slot()`.
    pub fn current_epoch(&self) -> Epoch {
        self.slot().epoch(T::slots_per_epoch())
    }

    /// The epoch prior to `self.current_epoch()`.
    ///
    /// If the current epoch is the genesis epoch, the genesis_epoch is returned.
    pub fn previous_epoch(&self) -> Epoch {
        let current_epoch = self.current_epoch();
        if current_epoch > T::genesis_epoch() {
            current_epoch
                .safe_sub(1)
                .expect("current epoch greater than genesis implies greater than 0")
        } else {
            current_epoch
        }
    }

    /// The epoch following `self.current_epoch()`.
    ///
    /// Spec v0.12.1
    pub fn next_epoch(&self) -> Result<Epoch, Error> {
        Ok(self.current_epoch().safe_add(1)?)
    }

    /// Compute the number of committees at `slot`.
    ///
    /// Makes use of the committee cache and will fail if no cache exists for the slot's epoch.
    ///
    /// Spec v0.12.1
    pub fn get_committee_count_at_slot(&self, slot: Slot) -> Result<u64, Error> {
        let cache = self.committee_cache_at_slot(slot)?;
        Ok(cache.committees_per_slot() as u64)
    }

    /// Compute the number of committees in an entire epoch.
    ///
    /// Spec v0.12.1
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

        Ok(cache.active_validator_indices())
    }

    /// Returns the active validator indices for the given epoch.
    ///
    /// Does not utilize the cache, performs a full iteration over the validator registry.
    pub fn get_active_validator_indices(
        &self,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<Vec<usize>, Error> {
        if epoch >= self.compute_activation_exit_epoch(self.current_epoch(), spec)? {
            Err(BeaconStateError::EpochOutOfBounds)
        } else {
            Ok(get_active_validator_indices(self.validators(), epoch))
        }
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
    /// Spec v0.12.1
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
    /// Spec v0.12.1
    pub fn get_beacon_committees_at_slot(&self, slot: Slot) -> Result<Vec<BeaconCommittee>, Error> {
        let cache = self.committee_cache_at_slot(slot)?;
        cache.get_beacon_committees_at_slot(slot)
    }

    /// Get all of the Beacon committees at a given relative epoch.
    ///
    /// Utilises the committee cache.
    ///
    /// Spec v0.12.1
    pub fn get_beacon_committees_at_epoch(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> Result<Vec<BeaconCommittee>, Error> {
        let cache = self.committee_cache(relative_epoch)?;
        cache.get_all_beacon_committees()
    }

    /// Returns the block root which decided the proposer shuffling for the current epoch. This root
    /// can be used to key this proposer shuffling.
    ///
    /// ## Notes
    ///
    /// The `block_root` covers the one-off scenario where the genesis block decides its own
    /// shuffling. It should be set to the latest block applied to `self` or the genesis block root.
    pub fn proposer_shuffling_decision_root(&self, block_root: Hash256) -> Result<Hash256, Error> {
        let decision_slot = self.proposer_shuffling_decision_slot();
        if self.slot() == decision_slot {
            Ok(block_root)
        } else {
            self.get_block_root(decision_slot).map(|root| *root)
        }
    }

    /// Returns the slot at which the proposer shuffling was decided. The block root at this slot
    /// can be used to key the proposer shuffling for the current epoch.
    fn proposer_shuffling_decision_slot(&self) -> Slot {
        self.current_epoch()
            .start_slot(T::slots_per_epoch())
            .saturating_sub(1_u64)
    }

    /// Returns the block root which decided the attester shuffling for the given `relative_epoch`.
    /// This root can be used to key that attester shuffling.
    ///
    /// ## Notes
    ///
    /// The `block_root` covers the one-off scenario where the genesis block decides its own
    /// shuffling. It should be set to the latest block applied to `self` or the genesis block root.
    pub fn attester_shuffling_decision_root(
        &self,
        block_root: Hash256,
        relative_epoch: RelativeEpoch,
    ) -> Result<Hash256, Error> {
        let decision_slot = self.attester_shuffling_decision_slot(relative_epoch);
        if self.slot() == decision_slot {
            Ok(block_root)
        } else {
            self.get_block_root(decision_slot).map(|root| *root)
        }
    }

    /// Returns the slot at which the proposer shuffling was decided. The block root at this slot
    /// can be used to key the proposer shuffling for the current epoch.
    fn attester_shuffling_decision_slot(&self, relative_epoch: RelativeEpoch) -> Slot {
        match relative_epoch {
            RelativeEpoch::Next => self.current_epoch(),
            RelativeEpoch::Current => self.previous_epoch(),
            RelativeEpoch::Previous => self.previous_epoch().saturating_sub(1_u64),
        }
        .start_slot(T::slots_per_epoch())
        .saturating_sub(1_u64)
    }

    /// Compute the proposer (not necessarily for the Beacon chain) from a list of indices.
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
            let shuffled_index = compute_shuffled_index(
                i.safe_rem(indices.len())?,
                indices.len(),
                seed,
                spec.shuffle_round_count,
            )
            .ok_or(Error::UnableToShuffle)?;
            let candidate_index = *indices
                .get(shuffled_index)
                .ok_or(Error::ShuffleIndexOutOfBounds(shuffled_index))?;
            let random_byte = Self::shuffling_random_byte(i, seed)?;
            let effective_balance = self.get_effective_balance(candidate_index)?;
            if effective_balance.safe_mul(MAX_RANDOM_BYTE)?
                >= spec
                    .max_effective_balance
                    .safe_mul(u64::from(random_byte))?
            {
                return Ok(candidate_index);
            }
            i.safe_add_assign(1)?;
        }
    }

    /// Get a random byte from the given `seed`.
    ///
    /// Used by the proposer & sync committee selection functions.
    fn shuffling_random_byte(i: usize, seed: &[u8]) -> Result<u8, Error> {
        let mut preimage = seed.to_vec();
        preimage.append(&mut int_to_bytes8(i.safe_div(32)? as u64));
        let index = i.safe_rem(32)?;
        hash(&preimage)
            .get(index)
            .copied()
            .ok_or(Error::ShuffleIndexOutOfBounds(index))
    }

    /// Return `true` if the validator who produced `slot_signature` is eligible to aggregate.
    ///
    /// Spec v0.12.1
    pub fn is_aggregator(
        &self,
        slot: Slot,
        index: CommitteeIndex,
        slot_signature: &Signature,
        spec: &ChainSpec,
    ) -> Result<bool, Error> {
        let committee = self.get_beacon_committee(slot, index)?;
        let modulo = std::cmp::max(
            1,
            (committee.committee.len() as u64).safe_div(spec.target_aggregators_per_committee)?,
        );
        let signature_hash = hash(&slot_signature.as_ssz_bytes());
        let signature_hash_int = u64::from_le_bytes(
            signature_hash
                .get(0..8)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Error::IsAggregatorOutOfBounds)?,
        );

        Ok(signature_hash_int.safe_rem(modulo)? == 0)
    }

    /// Returns the beacon proposer index for the `slot` in the given `relative_epoch`.
    ///
    /// Spec v0.12.1
    pub fn get_beacon_proposer_index(&self, slot: Slot, spec: &ChainSpec) -> Result<usize, Error> {
        // Proposer indices are only known for the current epoch, due to the dependence on the
        // effective balances of validators, which change at every epoch transition.
        let epoch = slot.epoch(T::slots_per_epoch());
        if epoch != self.current_epoch() {
            return Err(Error::SlotOutOfBounds);
        }

        let seed = self.get_beacon_proposer_seed(slot, spec)?;
        let indices = self.get_active_validator_indices(epoch, spec)?;

        self.compute_proposer_index(&indices, &seed, spec)
    }

    /// Returns the beacon proposer index for each `slot` in `self.current_epoch()`.
    ///
    /// The returned `Vec` contains one proposer index for each slot. For example, if
    /// `state.current_epoch() == 1`, then `vec[0]` refers to slot `32` and `vec[1]` refers to slot
    /// `33`. It will always be the case that `vec.len() == SLOTS_PER_EPOCH`.
    pub fn get_beacon_proposer_indices(&self, spec: &ChainSpec) -> Result<Vec<usize>, Error> {
        // Not using the cached validator indices since they are shuffled.
        let indices = self.get_active_validator_indices(self.current_epoch(), spec)?;

        self.current_epoch()
            .slot_iter(T::slots_per_epoch())
            .map(|slot| {
                let seed = self.get_beacon_proposer_seed(slot, spec)?;
                self.compute_proposer_index(&indices, &seed, spec)
            })
            .collect()
    }

    /// Compute the seed to use for the beacon proposer selection at the given `slot`.
    ///
    /// Spec v0.12.1
    pub fn get_beacon_proposer_seed(&self, slot: Slot, spec: &ChainSpec) -> Result<Vec<u8>, Error> {
        let epoch = slot.epoch(T::slots_per_epoch());
        let mut preimage = self
            .get_seed(epoch, Domain::BeaconProposer, spec)?
            .as_bytes()
            .to_vec();
        preimage.append(&mut int_to_bytes8(slot.as_u64()));
        Ok(hash(&preimage))
    }

    /// Get the already-built current or next sync committee from the state.
    pub fn get_built_sync_committee(
        &self,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<&Arc<SyncCommittee<T>>, Error> {
        let sync_committee_period = epoch.sync_committee_period(spec)?;
        let current_sync_committee_period = self.current_epoch().sync_committee_period(spec)?;
        let next_sync_committee_period = current_sync_committee_period.safe_add(1)?;

        if sync_committee_period == current_sync_committee_period {
            self.current_sync_committee()
        } else if sync_committee_period == next_sync_committee_period {
            self.next_sync_committee()
        } else {
            Err(Error::SyncCommitteeNotKnown {
                current_epoch: self.current_epoch(),
                epoch,
            })
        }
    }

    /// Get the validator indices of all validators from `sync_committee`.
    pub fn get_sync_committee_indices(
        &mut self,
        sync_committee: &SyncCommittee<T>,
    ) -> Result<Vec<usize>, Error> {
        sync_committee
            .pubkeys
            .iter()
            .map(|pubkey| {
                self.get_validator_index(pubkey)?
                    .ok_or(Error::PubkeyCacheInconsistent)
            })
            .collect()
    }

    /// Compute the sync committee indices for the next sync committee.
    fn get_next_sync_committee_indices(&self, spec: &ChainSpec) -> Result<Vec<usize>, Error> {
        let epoch = self.current_epoch().safe_add(1)?;

        let active_validator_indices = self.get_active_validator_indices(epoch, spec)?;
        let active_validator_count = active_validator_indices.len();

        let seed = self.get_seed(epoch, Domain::SyncCommittee, spec)?;

        let mut i = 0;
        let mut sync_committee_indices = Vec::with_capacity(T::SyncCommitteeSize::to_usize());
        while sync_committee_indices.len() < T::SyncCommitteeSize::to_usize() {
            let shuffled_index = compute_shuffled_index(
                i.safe_rem(active_validator_count)?,
                active_validator_count,
                seed.as_bytes(),
                spec.shuffle_round_count,
            )
            .ok_or(Error::UnableToShuffle)?;
            let candidate_index = *active_validator_indices
                .get(shuffled_index)
                .ok_or(Error::ShuffleIndexOutOfBounds(shuffled_index))?;
            let random_byte = Self::shuffling_random_byte(i, seed.as_bytes())?;
            let effective_balance = self.get_validator(candidate_index)?.effective_balance;
            if effective_balance.safe_mul(MAX_RANDOM_BYTE)?
                >= spec
                    .max_effective_balance
                    .safe_mul(u64::from(random_byte))?
            {
                sync_committee_indices.push(candidate_index);
            }
            i.safe_add_assign(1)?;
        }
        Ok(sync_committee_indices)
    }

    /// Compute the next sync committee.
    pub fn get_next_sync_committee(&self, spec: &ChainSpec) -> Result<SyncCommittee<T>, Error> {
        let sync_committee_indices = self.get_next_sync_committee_indices(spec)?;

        let pubkeys = sync_committee_indices
            .iter()
            .map(|&index| {
                self.validators()
                    .get(index)
                    .map(|v| v.pubkey)
                    .ok_or(Error::UnknownValidator(index))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let decompressed_pubkeys = pubkeys
            .iter()
            .map(|pk| pk.decompress())
            .collect::<Result<Vec<_>, _>>()?;
        let aggregate_pubkey = AggregatePublicKey::aggregate(&decompressed_pubkeys)?;

        Ok(SyncCommittee {
            pubkeys: FixedVector::new(pubkeys)?,
            aggregate_pubkey: aggregate_pubkey.to_public_key().compress(),
        })
    }

    /// Get the sync committee duties for a list of validator indices.
    ///
    /// Will return a `SyncCommitteeNotKnown` error if the `epoch` is out of bounds with respect
    /// to the current or next sync committee periods.
    pub fn get_sync_committee_duties(
        &self,
        epoch: Epoch,
        validator_indices: &[u64],
        spec: &ChainSpec,
    ) -> Result<Vec<Option<SyncDuty>>, Error> {
        let sync_committee = self.get_built_sync_committee(epoch, spec)?;

        validator_indices
            .iter()
            .map(|&validator_index| {
                let pubkey = self.get_validator(validator_index as usize)?.pubkey;

                Ok(SyncDuty::from_sync_committee(
                    validator_index,
                    pubkey,
                    sync_committee,
                ))
            })
            .collect()
    }

    /// Get the canonical root of the `latest_block_header`, filling in its state root if necessary.
    ///
    /// It needs filling in on all slots where there isn't a skip.
    ///
    /// Spec v0.12.1
    pub fn get_latest_block_root(&self, current_state_root: Hash256) -> Hash256 {
        if self.latest_block_header().state_root.is_zero() {
            let mut latest_block_header = self.latest_block_header().clone();
            latest_block_header.state_root = current_state_root;
            latest_block_header.canonical_root()
        } else {
            self.latest_block_header().canonical_root()
        }
    }

    /// Safely obtains the index for latest block roots, given some `slot`.
    ///
    /// Spec v0.12.1
    fn get_latest_block_roots_index(&self, slot: Slot) -> Result<usize, Error> {
        if slot < self.slot() && self.slot() <= slot.safe_add(self.block_roots().len() as u64)? {
            Ok(slot.as_usize().safe_rem(self.block_roots().len())?)
        } else {
            Err(BeaconStateError::SlotOutOfBounds)
        }
    }

    /// Returns an iterator across the past block roots of `state` in descending slot-order.
    ///
    /// See the docs for `BlockRootsIter` for more detail.
    pub fn rev_iter_block_roots<'a>(&'a self, spec: &ChainSpec) -> BlockRootsIter<'a, T> {
        BlockRootsIter::new(self, spec.genesis_slot)
    }

    /// Return the block root at a recent `slot`.
    pub fn get_block_root(&self, slot: Slot) -> Result<&Hash256, BeaconStateError> {
        let i = self.get_latest_block_roots_index(slot)?;
        self.block_roots()
            .get(i)
            .ok_or(Error::BlockRootsOutOfBounds(i))
    }

    /// Return the block root at a recent `epoch`.
    ///
    /// Note that the spec calls this `get_block_root`.
    pub fn get_block_root_at_epoch(&self, epoch: Epoch) -> Result<&Hash256, BeaconStateError> {
        self.get_block_root(epoch.start_slot(T::slots_per_epoch()))
    }

    /// Sets the block root for some given slot.
    pub fn set_block_root(
        &mut self,
        slot: Slot,
        block_root: Hash256,
    ) -> Result<(), BeaconStateError> {
        let i = self.get_latest_block_roots_index(slot)?;
        *self
            .block_roots_mut()
            .get_mut(i)
            .ok_or(Error::BlockRootsOutOfBounds(i))? = block_root;
        Ok(())
    }

    /// Fill `randao_mixes` with
    pub fn fill_randao_mixes_with(&mut self, index_root: Hash256) {
        *self.randao_mixes_mut() = FixedVector::from_elem(index_root);
    }

    /// Safely obtains the index for `randao_mixes`
    ///
    /// Spec v0.12.1
    fn get_randao_mix_index(
        &self,
        epoch: Epoch,
        allow_next_epoch: AllowNextEpoch,
    ) -> Result<usize, Error> {
        let current_epoch = self.current_epoch();
        let len = T::EpochsPerHistoricalVector::to_u64();

        if current_epoch < epoch.safe_add(len)?
            && epoch <= allow_next_epoch.upper_bound_of(current_epoch)?
        {
            Ok(epoch.as_usize().safe_rem(len as usize)?)
        } else {
            Err(Error::EpochOutOfBounds)
        }
    }

    /// XOR-assigns the existing `epoch` randao mix with the hash of the `signature`.
    ///
    /// # Errors:
    ///
    /// See `Self::get_randao_mix`.
    pub fn update_randao_mix(&mut self, epoch: Epoch, signature: &Signature) -> Result<(), Error> {
        let i = epoch
            .as_usize()
            .safe_rem(T::EpochsPerHistoricalVector::to_usize())?;

        let signature_hash = Hash256::from_slice(&hash(&ssz_encode(signature)));

        *self
            .randao_mixes_mut()
            .get_mut(i)
            .ok_or(Error::RandaoMixesOutOfBounds(i))? =
            *self.get_randao_mix(epoch)? ^ signature_hash;

        Ok(())
    }

    /// Return the randao mix at a recent ``epoch``.
    pub fn get_randao_mix(&self, epoch: Epoch) -> Result<&Hash256, Error> {
        let i = self.get_randao_mix_index(epoch, AllowNextEpoch::False)?;
        self.randao_mixes()
            .get(i)
            .ok_or(Error::RandaoMixesOutOfBounds(i))
    }

    /// Set the randao mix at a recent ``epoch``.
    ///
    /// Spec v0.12.1
    pub fn set_randao_mix(&mut self, epoch: Epoch, mix: Hash256) -> Result<(), Error> {
        let i = self.get_randao_mix_index(epoch, AllowNextEpoch::True)?;
        *self
            .randao_mixes_mut()
            .get_mut(i)
            .ok_or(Error::RandaoMixesOutOfBounds(i))? = mix;
        Ok(())
    }

    /// Safely obtains the index for latest state roots, given some `slot`.
    ///
    /// Spec v0.12.1
    fn get_latest_state_roots_index(&self, slot: Slot) -> Result<usize, Error> {
        if slot < self.slot() && self.slot() <= slot.safe_add(self.state_roots().len() as u64)? {
            Ok(slot.as_usize().safe_rem(self.state_roots().len())?)
        } else {
            Err(BeaconStateError::SlotOutOfBounds)
        }
    }

    /// Gets the state root for some slot.
    pub fn get_state_root(&self, slot: Slot) -> Result<&Hash256, Error> {
        let i = self.get_latest_state_roots_index(slot)?;
        self.state_roots()
            .get(i)
            .ok_or(Error::StateRootsOutOfBounds(i))
    }

    /// Gets the oldest (earliest slot) state root.
    pub fn get_oldest_state_root(&self) -> Result<&Hash256, Error> {
        let oldest_slot = self.slot().saturating_sub(self.state_roots().len());
        self.get_state_root(oldest_slot)
    }

    /// Gets the oldest (earliest slot) block root.
    pub fn get_oldest_block_root(&self) -> Result<&Hash256, Error> {
        let oldest_slot = self.slot().saturating_sub(self.block_roots().len());
        self.get_block_root(oldest_slot)
    }

    /// Sets the latest state root for slot.
    pub fn set_state_root(&mut self, slot: Slot, state_root: Hash256) -> Result<(), Error> {
        let i = self.get_latest_state_roots_index(slot)?;
        *self
            .state_roots_mut()
            .get_mut(i)
            .ok_or(Error::StateRootsOutOfBounds(i))? = state_root;
        Ok(())
    }

    /// Safely obtain the index for `slashings`, given some `epoch`.
    fn get_slashings_index(
        &self,
        epoch: Epoch,
        allow_next_epoch: AllowNextEpoch,
    ) -> Result<usize, Error> {
        // We allow the slashings vector to be accessed at any cached epoch at or before
        // the current epoch, or the next epoch if `AllowNextEpoch::True` is passed.
        let current_epoch = self.current_epoch();
        if current_epoch < epoch.safe_add(T::EpochsPerSlashingsVector::to_u64())?
            && epoch <= allow_next_epoch.upper_bound_of(current_epoch)?
        {
            Ok(epoch
                .as_usize()
                .safe_rem(T::EpochsPerSlashingsVector::to_usize())?)
        } else {
            Err(Error::EpochOutOfBounds)
        }
    }

    /// Get a reference to the entire `slashings` vector.
    pub fn get_all_slashings(&self) -> &[u64] {
        self.slashings()
    }

    /// Get the total slashed balances for some epoch.
    pub fn get_slashings(&self, epoch: Epoch) -> Result<u64, Error> {
        let i = self.get_slashings_index(epoch, AllowNextEpoch::False)?;
        self.slashings()
            .get(i)
            .copied()
            .ok_or(Error::SlashingsOutOfBounds(i))
    }

    /// Set the total slashed balances for some epoch.
    pub fn set_slashings(&mut self, epoch: Epoch, value: u64) -> Result<(), Error> {
        let i = self.get_slashings_index(epoch, AllowNextEpoch::True)?;
        *self
            .slashings_mut()
            .get_mut(i)
            .ok_or(Error::SlashingsOutOfBounds(i))? = value;
        Ok(())
    }

    /// Convenience accessor for validators and balances simultaneously.
    pub fn validators_and_balances_mut(&mut self) -> (&mut [Validator], &mut [u64]) {
        match self {
            BeaconState::Base(state) => (&mut state.validators, &mut state.balances),
            BeaconState::Altair(state) => (&mut state.validators, &mut state.balances),
        }
    }

    /// Generate a seed for the given `epoch`.
    pub fn get_seed(
        &self,
        epoch: Epoch,
        domain_type: Domain,
        spec: &ChainSpec,
    ) -> Result<Hash256, Error> {
        // Bypass the safe getter for RANDAO so we can gracefully handle the scenario where `epoch
        // == 0`.
        let mix = {
            let i = epoch
                .safe_add(T::EpochsPerHistoricalVector::to_u64())?
                .safe_sub(spec.min_seed_lookahead)?
                .safe_sub(1)?;
            let i_mod = i.as_usize().safe_rem(self.randao_mixes().len())?;
            self.randao_mixes()
                .get(i_mod)
                .ok_or(Error::RandaoMixesOutOfBounds(i_mod))?
        };
        let domain_bytes = int_to_bytes4(spec.get_domain_constant(domain_type));
        let epoch_bytes = int_to_bytes8(epoch.as_u64());

        const NUM_DOMAIN_BYTES: usize = 4;
        const NUM_EPOCH_BYTES: usize = 8;
        const MIX_OFFSET: usize = NUM_DOMAIN_BYTES + NUM_EPOCH_BYTES;
        const NUM_MIX_BYTES: usize = 32;

        let mut preimage = [0; NUM_DOMAIN_BYTES + NUM_EPOCH_BYTES + NUM_MIX_BYTES];
        preimage[0..NUM_DOMAIN_BYTES].copy_from_slice(&domain_bytes);
        preimage[NUM_DOMAIN_BYTES..MIX_OFFSET].copy_from_slice(&epoch_bytes);
        preimage[MIX_OFFSET..].copy_from_slice(mix.as_bytes());

        Ok(Hash256::from_slice(&hash(&preimage)))
    }

    /// Safe indexer for the `validators` list.
    pub fn get_validator(&self, validator_index: usize) -> Result<&Validator, Error> {
        self.validators()
            .get(validator_index)
            .ok_or(Error::UnknownValidator(validator_index))
    }

    /// Safe mutator for the `validators` list.
    pub fn get_validator_mut(&mut self, validator_index: usize) -> Result<&mut Validator, Error> {
        self.validators_mut()
            .get_mut(validator_index)
            .ok_or(Error::UnknownValidator(validator_index))
    }

    /// Return the effective balance for a validator with the given `validator_index`.
    pub fn get_effective_balance(&self, validator_index: usize) -> Result<u64, Error> {
        self.get_validator(validator_index)
            .map(|v| v.effective_balance)
    }

    /// Get the inactivity score for a single validator.
    ///
    /// Will error if the state lacks an `inactivity_scores` field.
    pub fn get_inactivity_score(&self, validator_index: usize) -> Result<u64, Error> {
        self.inactivity_scores()?
            .get(validator_index)
            .copied()
            .ok_or(Error::InactivityScoresOutOfBounds(validator_index))
    }

    /// Get a mutable reference to the inactivity score for a single validator.
    ///
    /// Will error if the state lacks an `inactivity_scores` field.
    pub fn get_inactivity_score_mut(&mut self, validator_index: usize) -> Result<&mut u64, Error> {
        self.inactivity_scores_mut()?
            .get_mut(validator_index)
            .ok_or(Error::InactivityScoresOutOfBounds(validator_index))
    }

    /// Get a mutable reference to the balance of a single validator.
    pub fn get_balance_mut(&mut self, validator_index: usize) -> Result<&mut u64, Error> {
        self.balances_mut()
            .get_mut(validator_index)
            .ok_or(Error::BalancesOutOfBounds(validator_index))
    }

    ///  Return the epoch at which an activation or exit triggered in ``epoch`` takes effect.
    ///
    ///  Spec v0.12.1
    pub fn compute_activation_exit_epoch(
        &self,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<Epoch, Error> {
        Ok(epoch.safe_add(1)?.safe_add(spec.max_seed_lookahead)?)
    }

    /// Return the churn limit for the current epoch (number of validators who can leave per epoch).
    ///
    /// Uses the epoch cache, and will error if it isn't initialized.
    ///
    /// Spec v0.12.1
    pub fn get_churn_limit(&self, spec: &ChainSpec) -> Result<u64, Error> {
        Ok(std::cmp::max(
            spec.min_per_epoch_churn_limit,
            (self
                .committee_cache(RelativeEpoch::Current)?
                .active_validator_count() as u64)
                .safe_div(spec.churn_limit_quotient)?,
        ))
    }

    /// Returns the `slot`, `index`, `committee_position` and `committee_len` for which a validator must produce an
    /// attestation.
    ///
    /// Note: Utilizes the cache and will fail if the appropriate cache is not initialized.
    ///
    /// Spec v0.12.1
    pub fn get_attestation_duties(
        &self,
        validator_index: usize,
        relative_epoch: RelativeEpoch,
    ) -> Result<Option<AttestationDuty>, Error> {
        let cache = self.committee_cache(relative_epoch)?;

        Ok(cache.get_attestation_duties(validator_index))
    }

    /// Implementation of `get_total_balance`, matching the spec.
    ///
    /// Returns minimum `EFFECTIVE_BALANCE_INCREMENT`, to avoid div by 0.
    pub fn get_total_balance<'a, I: IntoIterator<Item = &'a usize>>(
        &'a self,
        validator_indices: I,
        spec: &ChainSpec,
    ) -> Result<u64, Error> {
        let total_balance = validator_indices.into_iter().try_fold(0_u64, |acc, i| {
            self.get_effective_balance(*i)
                .and_then(|bal| Ok(acc.safe_add(bal)?))
        })?;
        Ok(std::cmp::max(
            total_balance,
            spec.effective_balance_increment,
        ))
    }

    /// Implementation of `get_total_active_balance`, matching the spec.
    ///
    /// Requires the total active balance cache to be initialised, which is initialised whenever
    /// the current committee cache is.
    ///
    /// Returns minimum `EFFECTIVE_BALANCE_INCREMENT`, to avoid div by 0.
    pub fn get_total_active_balance(&self) -> Result<u64, Error> {
        let (initialized_epoch, balance) = self
            .total_active_balance()
            .ok_or(Error::TotalActiveBalanceCacheUninitialized)?;

        let current_epoch = self.current_epoch();
        if initialized_epoch == current_epoch {
            Ok(balance)
        } else {
            Err(Error::TotalActiveBalanceCacheInconsistent {
                initialized_epoch,
                current_epoch,
            })
        }
    }

    /// Build the total active balance cache.
    ///
    /// This function requires the current committee cache to be already built. It is called
    /// automatically when `build_committee_cache` is called for the current epoch.
    fn build_total_active_balance_cache(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        // Order is irrelevant, so use the cached indices.
        let current_epoch = self.current_epoch();
        let total_active_balance = self.get_total_balance(
            self.get_cached_active_validator_indices(RelativeEpoch::Current)?,
            spec,
        )?;
        *self.total_active_balance_mut() = Some((current_epoch, total_active_balance));
        Ok(())
    }

    /// Set the cached total active balance to `None`, representing no known value.
    pub fn drop_total_active_balance_cache(&mut self) {
        *self.total_active_balance_mut() = None;
    }

    /// Get a mutable reference to the epoch participation flags for `epoch`.
    pub fn get_epoch_participation_mut(
        &mut self,
        epoch: Epoch,
    ) -> Result<&mut VariableList<ParticipationFlags, T::ValidatorRegistryLimit>, Error> {
        if epoch == self.current_epoch() {
            match self {
                BeaconState::Base(_) => Err(BeaconStateError::IncorrectStateVariant),
                BeaconState::Altair(state) => Ok(&mut state.current_epoch_participation),
            }
        } else if epoch == self.previous_epoch() {
            match self {
                BeaconState::Base(_) => Err(BeaconStateError::IncorrectStateVariant),
                BeaconState::Altair(state) => Ok(&mut state.previous_epoch_participation),
            }
        } else {
            Err(BeaconStateError::EpochOutOfBounds)
        }
    }

    /// Get the number of outstanding deposits.
    ///
    /// Returns `Err` if the state is invalid.
    pub fn get_outstanding_deposit_len(&self) -> Result<u64, Error> {
        self.eth1_data()
            .deposit_count
            .checked_sub(self.eth1_deposit_index())
            .ok_or(Error::InvalidDepositState {
                deposit_count: self.eth1_data().deposit_count,
                deposit_index: self.eth1_deposit_index(),
            })
    }

    /// Build all caches (except the tree hash cache), if they need to be built.
    pub fn build_all_caches(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        self.build_all_committee_caches(spec)?;
        self.update_pubkey_cache()?;
        self.build_exit_cache(spec)?;

        Ok(())
    }

    /// Build all committee caches, if they need to be built.
    pub fn build_all_committee_caches(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        self.build_committee_cache(RelativeEpoch::Previous, spec)?;
        self.build_committee_cache(RelativeEpoch::Current, spec)?;
        self.build_committee_cache(RelativeEpoch::Next, spec)?;
        Ok(())
    }

    /// Build the exit cache, if it needs to be built.
    pub fn build_exit_cache(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        if self.exit_cache().check_initialized().is_err() {
            *self.exit_cache_mut() = ExitCache::new(self.validators(), spec)?;
        }
        Ok(())
    }

    /// Drop all caches on the state.
    pub fn drop_all_caches(&mut self) -> Result<(), Error> {
        self.drop_total_active_balance_cache();
        self.drop_committee_cache(RelativeEpoch::Previous)?;
        self.drop_committee_cache(RelativeEpoch::Current)?;
        self.drop_committee_cache(RelativeEpoch::Next)?;
        self.drop_pubkey_cache();
        self.drop_tree_hash_cache();
        *self.exit_cache_mut() = ExitCache::default();
        Ok(())
    }

    /// Returns `true` if the committee cache for `relative_epoch` is built and ready to use.
    pub fn committee_cache_is_initialized(&self, relative_epoch: RelativeEpoch) -> bool {
        let i = Self::committee_cache_index(relative_epoch);

        self.committee_cache_at_index(i).map_or(false, |cache| {
            cache.is_initialized_at(relative_epoch.into_epoch(self.current_epoch()))
        })
    }

    /// Build an epoch cache, unless it is has already been built.
    pub fn build_committee_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let i = Self::committee_cache_index(relative_epoch);
        let is_initialized = self
            .committee_cache_at_index(i)?
            .is_initialized_at(relative_epoch.into_epoch(self.current_epoch()));

        if !is_initialized {
            self.force_build_committee_cache(relative_epoch, spec)?;
        }

        if self.total_active_balance().is_none() && relative_epoch == RelativeEpoch::Current {
            self.build_total_active_balance_cache(spec)?;
        }
        Ok(())
    }

    /// Always builds the previous epoch cache, even if it is already initialized.
    pub fn force_build_committee_cache(
        &mut self,
        relative_epoch: RelativeEpoch,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let epoch = relative_epoch.into_epoch(self.current_epoch());
        let i = Self::committee_cache_index(relative_epoch);

        *self.committee_cache_at_index_mut(i)? = self.initialize_committee_cache(epoch, spec)?;
        Ok(())
    }

    /// Initializes a new committee cache for the given `epoch`, regardless of whether one already
    /// exists. Returns the committee cache without attaching it to `self`.
    ///
    /// To build a cache and store it on `self`, use `Self::build_committee_cache`.
    pub fn initialize_committee_cache(
        &self,
        epoch: Epoch,
        spec: &ChainSpec,
    ) -> Result<CommitteeCache, Error> {
        CommitteeCache::initialized(self, epoch, spec)
    }

    /// Advances the cache for this state into the next epoch.
    ///
    /// This should be used if the `slot` of this state is advanced beyond an epoch boundary.
    ///
    /// Note: this function will not build any new committee caches, but will build the total
    /// balance cache if the (new) current epoch cache is initialized.
    pub fn advance_caches(&mut self, spec: &ChainSpec) -> Result<(), Error> {
        self.committee_caches_mut().rotate_left(1);

        // Re-compute total active balance for current epoch.
        //
        // This can only be computed once the state's effective balances have been updated
        // for the current epoch. I.e. it is not possible to know this value with the same
        // lookahead as the committee shuffling.
        let curr = Self::committee_cache_index(RelativeEpoch::Current);
        let curr_cache = mem::take(self.committee_cache_at_index_mut(curr)?);

        // If current epoch cache is initialized, compute the total active balance from its
        // indices. We check that the cache is initialized at the _next_ epoch because the slot has
        // not yet been advanced.
        let new_current_epoch = self.next_epoch()?;
        if curr_cache.is_initialized_at(new_current_epoch) {
            *self.total_active_balance_mut() = Some((
                new_current_epoch,
                self.get_total_balance(curr_cache.active_validator_indices(), spec)?,
            ));
        }
        // If the cache is not initialized, then the previous cached value for the total balance is
        // wrong, so delete it.
        else {
            self.drop_total_active_balance_cache();
        }
        *self.committee_cache_at_index_mut(curr)? = curr_cache;

        let next = Self::committee_cache_index(RelativeEpoch::Next);
        *self.committee_cache_at_index_mut(next)? = CommitteeCache::default();
        Ok(())
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

    /// Get the committee cache at a given index.
    fn committee_cache_at_index(&self, index: usize) -> Result<&CommitteeCache, Error> {
        self.committee_caches()
            .get(index)
            .ok_or(Error::CommitteeCachesOutOfBounds(index))
    }

    /// Get a mutable reference to the committee cache at a given index.
    fn committee_cache_at_index_mut(&mut self, index: usize) -> Result<&mut CommitteeCache, Error> {
        self.committee_caches_mut()
            .get_mut(index)
            .ok_or(Error::CommitteeCachesOutOfBounds(index))
    }

    /// Returns the cache for some `RelativeEpoch`. Returns an error if the cache has not been
    /// initialized.
    pub fn committee_cache(&self, relative_epoch: RelativeEpoch) -> Result<&CommitteeCache, Error> {
        let i = Self::committee_cache_index(relative_epoch);
        let cache = self.committee_cache_at_index(i)?;

        if cache.is_initialized_at(relative_epoch.into_epoch(self.current_epoch())) {
            Ok(cache)
        } else {
            Err(Error::CommitteeCacheUninitialized(Some(relative_epoch)))
        }
    }

    /// Drops the cache, leaving it in an uninitialized state.
    pub fn drop_committee_cache(&mut self, relative_epoch: RelativeEpoch) -> Result<(), Error> {
        *self.committee_cache_at_index_mut(Self::committee_cache_index(relative_epoch))? =
            CommitteeCache::default();
        Ok(())
    }

    /// Updates the pubkey cache, if required.
    ///
    /// Adds all `pubkeys` from the `validators` which are not already in the cache. Will
    /// never re-add a pubkey.
    pub fn update_pubkey_cache(&mut self) -> Result<(), Error> {
        let mut pubkey_cache = mem::take(self.pubkey_cache_mut());
        for (i, validator) in self
            .validators()
            .iter()
            .enumerate()
            .skip(pubkey_cache.len())
        {
            let success = pubkey_cache.insert(validator.pubkey, i);
            if !success {
                return Err(Error::PubkeyCacheInconsistent);
            }
        }
        *self.pubkey_cache_mut() = pubkey_cache;

        Ok(())
    }

    /// Completely drops the `pubkey_cache`, replacing it with a new, empty cache.
    pub fn drop_pubkey_cache(&mut self) {
        *self.pubkey_cache_mut() = PubkeyCache::default()
    }

    /// Initialize but don't fill the tree hash cache, if it isn't already initialized.
    pub fn initialize_tree_hash_cache(&mut self) {
        if !self.tree_hash_cache().is_initialized() {
            *self.tree_hash_cache_mut() = BeaconTreeHashCache::new(self)
        }
    }

    /// Compute the tree hash root of the state using the tree hash cache.
    ///
    /// Initialize the tree hash cache if it isn't already initialized.
    pub fn update_tree_hash_cache(&mut self) -> Result<Hash256, Error> {
        self.initialize_tree_hash_cache();

        let cache = self.tree_hash_cache_mut().take();

        if let Some(mut cache) = cache {
            // Note: we return early if the tree hash fails, leaving `self.tree_hash_cache` as
            // None. There's no need to keep a cache that fails.
            let root = cache.recalculate_tree_hash_root(self)?;
            self.tree_hash_cache_mut().restore(cache);
            Ok(root)
        } else {
            Err(Error::TreeHashCacheNotInitialized)
        }
    }

    /// Compute the tree hash root of the validators using the tree hash cache.
    ///
    /// Initialize the tree hash cache if it isn't already initialized.
    pub fn update_validators_tree_hash_cache(&mut self) -> Result<Hash256, Error> {
        self.initialize_tree_hash_cache();

        let cache = self.tree_hash_cache_mut().take();

        if let Some(mut cache) = cache {
            // Note: we return early if the tree hash fails, leaving `self.tree_hash_cache` as
            // None. There's no need to keep a cache that fails.
            let root = cache.recalculate_validators_tree_hash_root(self.validators())?;
            self.tree_hash_cache_mut().restore(cache);
            Ok(root)
        } else {
            Err(Error::TreeHashCacheNotInitialized)
        }
    }

    /// Completely drops the tree hash cache, replacing it with a new, empty cache.
    pub fn drop_tree_hash_cache(&mut self) {
        self.tree_hash_cache_mut().uninitialize();
    }

    /// Clone the state whilst preserving only the selected caches.
    pub fn clone_with(&self, config: CloneConfig) -> Self {
        let mut res = match self {
            BeaconState::Base(inner) => BeaconState::Base(inner.clone()),
            BeaconState::Altair(inner) => BeaconState::Altair(inner.clone()),
        };
        if config.committee_caches {
            *res.committee_caches_mut() = self.committee_caches().clone();
            *res.total_active_balance_mut() = *self.total_active_balance();
        }
        if config.pubkey_cache {
            *res.pubkey_cache_mut() = self.pubkey_cache().clone();
        }
        if config.exit_cache {
            *res.exit_cache_mut() = self.exit_cache().clone();
        }
        if config.tree_hash_cache {
            *res.tree_hash_cache_mut() = self.tree_hash_cache().clone();
        }
        res
    }

    pub fn clone_with_only_committee_caches(&self) -> Self {
        self.clone_with(CloneConfig::committee_caches_only())
    }

    pub fn is_eligible_validator(&self, val_index: usize) -> Result<bool, Error> {
        let previous_epoch = self.previous_epoch();
        self.get_validator(val_index).map(|val| {
            val.is_active_at(previous_epoch)
                || (val.slashed && previous_epoch + Epoch::new(1) < val.withdrawable_epoch)
        })
    }

    pub fn is_in_inactivity_leak(&self, spec: &ChainSpec) -> bool {
        (self.previous_epoch() - self.finalized_checkpoint().epoch)
            > spec.min_epochs_to_inactivity_penalty
    }

    /// Get the `SyncCommittee` associated with the next slot. Useful because sync committees
    /// assigned to `slot` sign for `slot - 1`. This creates the exceptional logic below when
    /// transitioning between sync committee periods.
    pub fn get_sync_committee_for_next_slot(
        &self,
        spec: &ChainSpec,
    ) -> Result<Arc<SyncCommittee<T>>, Error> {
        let next_slot_epoch = self
            .slot()
            .saturating_add(Slot::new(1))
            .epoch(T::slots_per_epoch());

        let sync_committee = if self.current_epoch().sync_committee_period(spec)
            == next_slot_epoch.sync_committee_period(spec)
        {
            self.current_sync_committee()?.clone()
        } else {
            self.next_sync_committee()?.clone()
        };
        Ok(sync_committee)
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

impl From<bls::Error> for Error {
    fn from(e: bls::Error) -> Error {
        Error::BlsError(e)
    }
}

impl From<cached_tree_hash::Error> for Error {
    fn from(e: cached_tree_hash::Error) -> Error {
        Error::CachedTreeHashError(e)
    }
}

impl From<tree_hash::Error> for Error {
    fn from(e: tree_hash::Error) -> Error {
        Error::TreeHashError(e)
    }
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Error {
        Error::ArithError(e)
    }
}

/// Helper function for "cloning" a field by using its default value.
fn clone_default<T: Default>(_value: &T) -> T {
    T::default()
}

impl<T: EthSpec> CompareFields for BeaconState<T> {
    fn compare_fields(&self, other: &Self) -> Vec<compare_fields::Comparison> {
        match (self, other) {
            (BeaconState::Base(x), BeaconState::Base(y)) => x.compare_fields(y),
            (BeaconState::Altair(x), BeaconState::Altair(y)) => x.compare_fields(y),
            _ => panic!("compare_fields: mismatched state variants"),
        }
    }
}
