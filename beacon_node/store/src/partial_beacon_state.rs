use crate::chunked_vector::{
    load_variable_list_from_db, load_vector_from_db, BlockRoots, HistoricalRoots, RandaoMixes,
    StateRoots,
};
use crate::{get_key_for_col, DBColumn, Error, KeyValueStore, KeyValueStoreOp};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::convert::TryInto;
use std::sync::Arc;
use types::superstruct;
use types::*;

/// Lightweight variant of the `BeaconState` that is stored in the database.
///
/// Utilises lazy-loading from separate storage for its vector fields.
#[superstruct(
    variants(Base, Altair),
    variant_attributes(derive(Debug, PartialEq, Clone, Encode, Decode),)
)]
#[derive(Debug, PartialEq, Clone, Encode)]
#[ssz(enum_behaviour = "transparent")]
pub struct PartialBeaconState<T>
where
    T: EthSpec,
{
    // Versioning
    pub genesis_time: u64,
    pub genesis_validators_root: Hash256,
    #[superstruct(getter(copy))]
    pub slot: Slot,
    pub fork: Fork,

    // History
    pub latest_block_header: BeaconBlockHeader,

    #[ssz(skip_serializing, skip_deserializing)]
    pub block_roots: Option<FixedVector<Hash256, T::SlotsPerHistoricalRoot>>,
    #[ssz(skip_serializing, skip_deserializing)]
    pub state_roots: Option<FixedVector<Hash256, T::SlotsPerHistoricalRoot>>,

    #[ssz(skip_serializing, skip_deserializing)]
    pub historical_roots: Option<VariableList<Hash256, T::HistoricalRootsLimit>>,

    // Ethereum 1.0 chain data
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: VariableList<Eth1Data, T::SlotsPerEth1VotingPeriod>,
    pub eth1_deposit_index: u64,

    // Registry
    pub validators: VariableList<Validator, T::ValidatorRegistryLimit>,
    pub balances: VariableList<u64, T::ValidatorRegistryLimit>,

    // Shuffling
    /// Randao value from the current slot, for patching into the per-epoch randao vector.
    pub latest_randao_value: Hash256,
    #[ssz(skip_serializing, skip_deserializing)]
    pub randao_mixes: Option<FixedVector<Hash256, T::EpochsPerHistoricalVector>>,

    // Slashings
    slashings: FixedVector<u64, T::EpochsPerSlashingsVector>,

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
    pub justification_bits: BitVector<T::JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // Inactivity
    #[superstruct(only(Altair))]
    pub inactivity_scores: VariableList<u64, T::ValidatorRegistryLimit>,

    // Light-client sync committees
    #[superstruct(only(Altair))]
    pub current_sync_committee: Arc<SyncCommittee<T>>,
    #[superstruct(only(Altair))]
    pub next_sync_committee: Arc<SyncCommittee<T>>,
}

/// Implement the conversion function from BeaconState -> PartialBeaconState.
macro_rules! impl_from_state_forgetful {
    ($s:ident, $outer:ident, $variant_name:ident, $struct_name:ident, [$($extra_fields:ident),*]) => {
        PartialBeaconState::$variant_name($struct_name {
            // Versioning
            genesis_time: $s.genesis_time,
            genesis_validators_root: $s.genesis_validators_root,
            slot: $s.slot,
            fork: $s.fork,

            // History
            latest_block_header: $s.latest_block_header.clone(),
            block_roots: None,
            state_roots: None,
            historical_roots: None,

            // Eth1
            eth1_data: $s.eth1_data.clone(),
            eth1_data_votes: $s.eth1_data_votes.clone(),
            eth1_deposit_index: $s.eth1_deposit_index,

            // Validator registry
            validators: $s.validators.clone(),
            balances: $s.balances.clone(),

            // Shuffling
            latest_randao_value: *$outer
                .get_randao_mix($outer.current_epoch())
                .expect("randao at current epoch is OK"),
            randao_mixes: None,

            // Slashings
            slashings: $s.slashings.clone(),

            // Finality
            justification_bits: $s.justification_bits.clone(),
            previous_justified_checkpoint: $s.previous_justified_checkpoint,
            current_justified_checkpoint: $s.current_justified_checkpoint,
            finalized_checkpoint: $s.finalized_checkpoint,

            // Variant-specific fields
            $(
                $extra_fields: $s.$extra_fields.clone()
            ),*
        })
    }
}

impl<T: EthSpec> PartialBeaconState<T> {
    /// Convert a `BeaconState` to a `PartialBeaconState`, while dropping the optional fields.
    pub fn from_state_forgetful(outer: &BeaconState<T>) -> Self {
        match outer {
            BeaconState::Base(s) => impl_from_state_forgetful!(
                s,
                outer,
                Base,
                PartialBeaconStateBase,
                [previous_epoch_attestations, current_epoch_attestations]
            ),
            BeaconState::Altair(s) => impl_from_state_forgetful!(
                s,
                outer,
                Altair,
                PartialBeaconStateAltair,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores
                ]
            ),
        }
    }

    /// SSZ decode.
    pub fn from_ssz_bytes(bytes: &[u8], spec: &ChainSpec) -> Result<Self, ssz::DecodeError> {
        // Slot is after genesis_time (u64) and genesis_validators_root (Hash256).
        let slot_offset = <u64 as Decode>::ssz_fixed_len() + <Hash256 as Decode>::ssz_fixed_len();
        let slot_len = <Slot as Decode>::ssz_fixed_len();
        let slot_bytes = bytes.get(slot_offset..slot_offset + slot_len).ok_or(
            DecodeError::InvalidByteLength {
                len: bytes.len(),
                expected: slot_offset + slot_len,
            },
        )?;

        let slot = Slot::from_ssz_bytes(slot_bytes)?;
        let epoch = slot.epoch(T::slots_per_epoch());

        if spec
            .altair_fork_epoch
            .map_or(true, |altair_epoch| epoch < altair_epoch)
        {
            PartialBeaconStateBase::from_ssz_bytes(bytes).map(Self::Base)
        } else {
            PartialBeaconStateAltair::from_ssz_bytes(bytes).map(Self::Altair)
        }
    }

    /// Prepare the partial state for storage in the KV database.
    pub fn as_kv_store_op(&self, state_root: Hash256) -> KeyValueStoreOp {
        let db_key = get_key_for_col(DBColumn::BeaconState.into(), state_root.as_bytes());
        KeyValueStoreOp::PutKeyValue(db_key, self.as_ssz_bytes())
    }

    pub fn load_block_roots<S: KeyValueStore<T>>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.block_roots().is_none() {
            *self.block_roots_mut() = Some(load_vector_from_db::<BlockRoots, T, _>(
                store,
                self.slot(),
                spec,
            )?);
        }
        Ok(())
    }

    pub fn load_state_roots<S: KeyValueStore<T>>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.state_roots().is_none() {
            *self.state_roots_mut() = Some(load_vector_from_db::<StateRoots, T, _>(
                store,
                self.slot(),
                spec,
            )?);
        }
        Ok(())
    }

    pub fn load_historical_roots<S: KeyValueStore<T>>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.historical_roots().is_none() {
            *self.historical_roots_mut() = Some(
                load_variable_list_from_db::<HistoricalRoots, T, _>(store, self.slot(), spec)?,
            );
        }
        Ok(())
    }

    pub fn load_randao_mixes<S: KeyValueStore<T>>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.randao_mixes().is_none() {
            // Load the per-epoch values from the database
            let mut randao_mixes =
                load_vector_from_db::<RandaoMixes, T, _>(store, self.slot(), spec)?;

            // Patch the value for the current slot into the index for the current epoch
            let current_epoch = self.slot().epoch(T::slots_per_epoch());
            let len = randao_mixes.len();
            randao_mixes[current_epoch.as_usize() % len] = *self.latest_randao_value();

            *self.randao_mixes_mut() = Some(randao_mixes)
        }
        Ok(())
    }
}

/// Implement the conversion from PartialBeaconState -> BeaconState.
macro_rules! impl_try_into_beacon_state {
    ($inner:ident, $variant_name:ident, $struct_name:ident, [$($extra_fields:ident),*]) => {
        BeaconState::$variant_name($struct_name {
            // Versioning
            genesis_time: $inner.genesis_time,
            genesis_validators_root: $inner.genesis_validators_root,
            slot: $inner.slot,
            fork: $inner.fork,

            // History
            latest_block_header: $inner.latest_block_header,
            block_roots: unpack_field($inner.block_roots)?,
            state_roots: unpack_field($inner.state_roots)?,
            historical_roots: unpack_field($inner.historical_roots)?,

            // Eth1
            eth1_data: $inner.eth1_data,
            eth1_data_votes: $inner.eth1_data_votes,
            eth1_deposit_index: $inner.eth1_deposit_index,

            // Validator registry
            validators: $inner.validators,
            balances: $inner.balances,

            // Shuffling
            randao_mixes: unpack_field($inner.randao_mixes)?,

            // Slashings
            slashings: $inner.slashings,

            // Finality
            justification_bits: $inner.justification_bits,
            previous_justified_checkpoint: $inner.previous_justified_checkpoint,
            current_justified_checkpoint: $inner.current_justified_checkpoint,
            finalized_checkpoint: $inner.finalized_checkpoint,

            // Caching
            total_active_balance: <_>::default(),
            committee_caches: <_>::default(),
            pubkey_cache: <_>::default(),
            exit_cache: <_>::default(),
            tree_hash_cache: <_>::default(),

            // Variant-specific fields
            $(
                $extra_fields: $inner.$extra_fields
            ),*
        })
    }
}

fn unpack_field<T>(x: Option<T>) -> Result<T, Error> {
    x.ok_or(Error::PartialBeaconStateError)
}

impl<E: EthSpec> TryInto<BeaconState<E>> for PartialBeaconState<E> {
    type Error = Error;

    fn try_into(self) -> Result<BeaconState<E>, Error> {
        let state = match self {
            PartialBeaconState::Base(inner) => impl_try_into_beacon_state!(
                inner,
                Base,
                BeaconStateBase,
                [previous_epoch_attestations, current_epoch_attestations]
            ),
            PartialBeaconState::Altair(inner) => impl_try_into_beacon_state!(
                inner,
                Altair,
                BeaconStateAltair,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores
                ]
            ),
        };
        Ok(state)
    }
}
