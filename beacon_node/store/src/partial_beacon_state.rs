use crate::chunked_vector::{
    load_variable_list_from_db, load_vector_from_db, ActiveIndexRoots, BlockRoots,
    CompactCommitteesRoots, HistoricalRoots, RandaoMixes, StateRoots,
};
use crate::{Error, Store};
use ssz_derive::{Decode, Encode};
use std::convert::TryInto;
use types::*;

/// Lightweight variant of the `BeaconState` that is stored in the database.
///
/// Utilises lazy-loading from separate storage for its vector fields.
///
/// Spec v0.8.1
#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct PartialBeaconState<T>
where
    T: EthSpec,
{
    // Versioning
    pub genesis_time: u64,
    pub slot: Slot,
    pub fork: Fork,

    // History
    pub latest_block_header: BeaconBlockHeader,

    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    pub block_roots: Option<FixedVector<Hash256, T::SlotsPerHistoricalRoot>>,
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    pub state_roots: Option<FixedVector<Hash256, T::SlotsPerHistoricalRoot>>,

    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    pub historical_roots: Option<VariableList<Hash256, T::HistoricalRootsLimit>>,

    // Ethereum 1.0 chain data
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: VariableList<Eth1Data, T::SlotsPerEth1VotingPeriod>,
    pub eth1_deposit_index: u64,

    // Registry
    pub validators: VariableList<Validator, T::ValidatorRegistryLimit>,
    pub balances: VariableList<u64, T::ValidatorRegistryLimit>,

    // Shuffling
    pub start_shard: u64,

    /// Randao value from the current slot, for patching into the per-epoch randao vector.
    pub latest_randao_value: Hash256,
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    pub randao_mixes: Option<FixedVector<Hash256, T::EpochsPerHistoricalVector>>,
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    pub active_index_roots: Option<FixedVector<Hash256, T::EpochsPerHistoricalVector>>,
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    pub compact_committees_roots: Option<FixedVector<Hash256, T::EpochsPerHistoricalVector>>,

    // Slashings
    slashings: FixedVector<u64, T::EpochsPerSlashingsVector>,

    // Attestations
    pub previous_epoch_attestations: VariableList<PendingAttestation<T>, T::MaxPendingAttestations>,
    pub current_epoch_attestations: VariableList<PendingAttestation<T>, T::MaxPendingAttestations>,

    // Crosslinks
    pub previous_crosslinks: FixedVector<Crosslink, T::ShardCount>,
    pub current_crosslinks: FixedVector<Crosslink, T::ShardCount>,

    // Finality
    pub justification_bits: BitVector<T::JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // Caching (not in the spec)
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    pub committee_caches: [CommitteeCache; CACHED_EPOCHS],
}

impl<T: EthSpec> PartialBeaconState<T> {
    /// Convert a `BeaconState` to a `PartialBeaconState`, while dropping the optional fields.
    pub fn from_state_forgetful(s: &BeaconState<T>) -> Self {
        // TODO: could use references/Cow for fields to avoid cloning
        PartialBeaconState {
            genesis_time: s.genesis_time,
            slot: s.slot,
            fork: s.fork.clone(),

            // History
            latest_block_header: s.latest_block_header.clone(),
            block_roots: None,
            state_roots: None,
            historical_roots: None,

            // Eth1
            eth1_data: s.eth1_data.clone(),
            eth1_data_votes: s.eth1_data_votes.clone(),
            eth1_deposit_index: s.eth1_deposit_index,

            // Validator registry
            validators: s.validators.clone(),
            balances: s.balances.clone(),

            // Shuffling
            start_shard: s.start_shard,
            latest_randao_value: *s
                .get_randao_mix(s.current_epoch())
                .expect("randao at current epoch is OK"),
            randao_mixes: None,
            active_index_roots: None,
            compact_committees_roots: None,

            // Slashings
            slashings: s.get_all_slashings().to_vec().into(),

            // Attestations
            previous_epoch_attestations: s.previous_epoch_attestations.clone(),
            current_epoch_attestations: s.current_epoch_attestations.clone(),

            // Crosslinks
            previous_crosslinks: s.previous_crosslinks.clone(),
            current_crosslinks: s.current_crosslinks.clone(),

            // Finality
            justification_bits: s.justification_bits.clone(),
            previous_justified_checkpoint: s.previous_justified_checkpoint.clone(),
            current_justified_checkpoint: s.current_justified_checkpoint.clone(),
            finalized_checkpoint: s.finalized_checkpoint.clone(),

            // Caching
            committee_caches: s.committee_caches.clone(),
        }
    }

    pub fn load_block_roots<S: Store>(&mut self, store: &S, spec: &ChainSpec) -> Result<(), Error> {
        if self.block_roots.is_none() {
            self.block_roots = Some(load_vector_from_db::<BlockRoots, T, _>(
                store, self.slot, spec,
            )?);
        }
        Ok(())
    }

    pub fn load_state_roots<S: Store>(&mut self, store: &S, spec: &ChainSpec) -> Result<(), Error> {
        if self.state_roots.is_none() {
            self.state_roots = Some(load_vector_from_db::<StateRoots, T, _>(
                store, self.slot, spec,
            )?);
        }
        Ok(())
    }

    pub fn load_historical_roots<S: Store>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.historical_roots.is_none() {
            self.historical_roots = Some(load_variable_list_from_db::<HistoricalRoots, T, _>(
                store, self.slot, spec,
            )?);
        }
        Ok(())
    }

    pub fn load_randao_mixes<S: Store>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.randao_mixes.is_none() {
            // Load the per-epoch values from the database
            let mut randao_mixes =
                load_vector_from_db::<RandaoMixes, T, _>(store, self.slot, spec)?;

            // Patch the value for the current slot into the index for the current epoch
            let current_epoch = self.slot.epoch(T::slots_per_epoch());
            let len = randao_mixes.len();
            randao_mixes[current_epoch.as_usize() % len] = self.latest_randao_value;

            self.randao_mixes = Some(randao_mixes)
        }
        Ok(())
    }

    pub fn load_active_index_roots<S: Store>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.active_index_roots.is_none() {
            self.active_index_roots = Some(load_vector_from_db::<ActiveIndexRoots, T, _>(
                store, self.slot, spec,
            )?);
        }
        Ok(())
    }

    pub fn load_compact_committees_roots<S: Store>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.compact_committees_roots.is_none() {
            self.compact_committees_roots =
                Some(load_vector_from_db::<CompactCommitteesRoots, T, _>(
                    store, self.slot, spec,
                )?);
        }
        Ok(())
    }
}

impl<E: EthSpec> TryInto<BeaconState<E>> for PartialBeaconState<E> {
    type Error = Error;

    fn try_into(self) -> Result<BeaconState<E>, Error> {
        fn unpack<T>(x: Option<T>) -> Result<T, Error> {
            x.ok_or(Error::PartialBeaconStateError)
        }

        Ok(BeaconState {
            genesis_time: self.genesis_time,
            slot: self.slot,
            fork: self.fork,

            // History
            latest_block_header: self.latest_block_header,
            block_roots: unpack(self.block_roots)?,
            state_roots: unpack(self.state_roots)?,
            historical_roots: unpack(self.historical_roots)?,

            // Eth1
            eth1_data: self.eth1_data,
            eth1_data_votes: self.eth1_data_votes,
            eth1_deposit_index: self.eth1_deposit_index,

            // Validator registry
            validators: self.validators,
            balances: self.balances,

            // Shuffling
            start_shard: self.start_shard,
            randao_mixes: unpack(self.randao_mixes)?,
            active_index_roots: unpack(self.active_index_roots)?,
            compact_committees_roots: unpack(self.compact_committees_roots)?,

            // Slashings
            slashings: self.slashings,

            // Attestations
            previous_epoch_attestations: self.previous_epoch_attestations,
            current_epoch_attestations: self.current_epoch_attestations,

            // Crosslinks
            previous_crosslinks: self.previous_crosslinks,
            current_crosslinks: self.current_crosslinks,

            // Finality
            justification_bits: self.justification_bits,
            previous_justified_checkpoint: self.previous_justified_checkpoint,
            current_justified_checkpoint: self.current_justified_checkpoint,
            finalized_checkpoint: self.finalized_checkpoint,

            // Caching
            committee_caches: self.committee_caches,
            pubkey_cache: <_>::default(),
            exit_cache: <_>::default(),
        })
    }
}
