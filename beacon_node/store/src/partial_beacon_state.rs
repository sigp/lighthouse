use crate::chunked_vector::{
    load_variable_list_from_db, load_vector_from_db, BlockRoots, HistoricalRoots,
    HistoricalSummaries, RandaoMixes, StateRoots,
};
use crate::{get_key_for_col, DBColumn, Error, KeyValueStore, KeyValueStoreOp};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use types::historical_summary::HistoricalSummary;
use types::superstruct;
use types::*;

/// Lightweight variant of the `BeaconState` that is stored in the database.
///
/// Utilises lazy-loading from separate storage for its vector fields.
#[superstruct(
    variants(Base, Altair, Bellatrix, Capella, Deneb, Electra),
    variant_attributes(derive(Debug, PartialEq, Clone, Encode, Decode))
)]
#[derive(Debug, PartialEq, Clone, Encode)]
#[ssz(enum_behaviour = "transparent")]
pub struct PartialBeaconState<E>
where
    E: EthSpec,
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
    pub block_roots: Option<Vector<Hash256, E::SlotsPerHistoricalRoot>>,
    #[ssz(skip_serializing, skip_deserializing)]
    pub state_roots: Option<Vector<Hash256, E::SlotsPerHistoricalRoot>>,

    #[ssz(skip_serializing, skip_deserializing)]
    pub historical_roots: Option<List<Hash256, E::HistoricalRootsLimit>>,

    // Ethereum 1.0 chain data
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: List<Eth1Data, E::SlotsPerEth1VotingPeriod>,
    pub eth1_deposit_index: u64,

    // Registry
    pub validators: List<Validator, E::ValidatorRegistryLimit>,
    pub balances: List<u64, E::ValidatorRegistryLimit>,

    // Shuffling
    /// Randao value from the current slot, for patching into the per-epoch randao vector.
    pub latest_randao_value: Hash256,
    #[ssz(skip_serializing, skip_deserializing)]
    pub randao_mixes: Option<Vector<Hash256, E::EpochsPerHistoricalVector>>,

    // Slashings
    slashings: Vector<u64, E::EpochsPerSlashingsVector>,

    // Attestations (genesis fork only)
    #[superstruct(only(Base))]
    pub previous_epoch_attestations: List<PendingAttestation<E>, E::MaxPendingAttestations>,
    #[superstruct(only(Base))]
    pub current_epoch_attestations: List<PendingAttestation<E>, E::MaxPendingAttestations>,

    // Participation (Altair and later)
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra))]
    pub previous_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra))]
    pub current_epoch_participation: List<ParticipationFlags, E::ValidatorRegistryLimit>,

    // Finality
    pub justification_bits: BitVector<E::JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // Inactivity
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra))]
    pub inactivity_scores: List<u64, E::ValidatorRegistryLimit>,

    // Light-client sync committees
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra))]
    pub current_sync_committee: Arc<SyncCommittee<E>>,
    #[superstruct(only(Altair, Bellatrix, Capella, Deneb, Electra))]
    pub next_sync_committee: Arc<SyncCommittee<E>>,

    // Execution
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "latest_execution_payload_header_bellatrix")
    )]
    pub latest_execution_payload_header: ExecutionPayloadHeaderBellatrix<E>,
    #[superstruct(
        only(Capella),
        partial_getter(rename = "latest_execution_payload_header_capella")
    )]
    pub latest_execution_payload_header: ExecutionPayloadHeaderCapella<E>,
    #[superstruct(
        only(Deneb),
        partial_getter(rename = "latest_execution_payload_header_deneb")
    )]
    pub latest_execution_payload_header: ExecutionPayloadHeaderDeneb<E>,
    #[superstruct(
        only(Electra),
        partial_getter(rename = "latest_execution_payload_header_electra")
    )]
    pub latest_execution_payload_header: ExecutionPayloadHeaderElectra<E>,

    // Capella
    #[superstruct(only(Capella, Deneb, Electra))]
    pub next_withdrawal_index: u64,
    #[superstruct(only(Capella, Deneb, Electra))]
    pub next_withdrawal_validator_index: u64,

    #[ssz(skip_serializing, skip_deserializing)]
    #[superstruct(only(Capella, Deneb, Electra))]
    pub historical_summaries: Option<List<HistoricalSummary, E::HistoricalRootsLimit>>,

    // Electra
    #[superstruct(only(Electra))]
    pub deposit_receipts_start_index: u64,
    #[superstruct(only(Electra))]
    pub deposit_balance_to_consume: u64,
    #[superstruct(only(Electra))]
    pub exit_balance_to_consume: u64,
    #[superstruct(only(Electra))]
    pub earliest_exit_epoch: Epoch,
    #[superstruct(only(Electra))]
    pub consolidation_balance_to_consume: u64,
    #[superstruct(only(Electra))]
    pub earliest_consolidation_epoch: Epoch,

    // TODO(electra) should these be optional?
    #[superstruct(only(Electra))]
    pub pending_balance_deposits: List<PendingBalanceDeposit, E::PendingBalanceDepositsLimit>,
    #[superstruct(only(Electra))]
    pub pending_partial_withdrawals:
        List<PendingPartialWithdrawal, E::PendingPartialWithdrawalsLimit>,
    #[superstruct(only(Electra))]
    pub pending_consolidations: List<PendingConsolidation, E::PendingConsolidationsLimit>,
}

/// Implement the conversion function from BeaconState -> PartialBeaconState.
macro_rules! impl_from_state_forgetful {
    ($s:ident, $outer:ident, $variant_name:ident, $struct_name:ident, [$($extra_fields:ident),*], [$($extra_fields_opt:ident),*]) => {
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
            ),*,

            // Variant-specific optional
            $(
                $extra_fields_opt: None
            ),*
        })
    }
}

impl<E: EthSpec> PartialBeaconState<E> {
    /// Convert a `BeaconState` to a `PartialBeaconState`, while dropping the optional fields.
    pub fn from_state_forgetful(outer: &BeaconState<E>) -> Self {
        match outer {
            BeaconState::Base(s) => impl_from_state_forgetful!(
                s,
                outer,
                Base,
                PartialBeaconStateBase,
                [previous_epoch_attestations, current_epoch_attestations],
                []
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
                ],
                []
            ),
            BeaconState::Bellatrix(s) => impl_from_state_forgetful!(
                s,
                outer,
                Bellatrix,
                PartialBeaconStateBellatrix,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header
                ],
                []
            ),
            BeaconState::Capella(s) => impl_from_state_forgetful!(
                s,
                outer,
                Capella,
                PartialBeaconStateCapella,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header,
                    next_withdrawal_index,
                    next_withdrawal_validator_index
                ],
                [historical_summaries]
            ),
            BeaconState::Deneb(s) => impl_from_state_forgetful!(
                s,
                outer,
                Deneb,
                PartialBeaconStateDeneb,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header,
                    next_withdrawal_index,
                    next_withdrawal_validator_index
                ],
                [historical_summaries]
            ),
            BeaconState::Electra(s) => impl_from_state_forgetful!(
                s,
                outer,
                Electra,
                PartialBeaconStateElectra,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header,
                    next_withdrawal_index,
                    next_withdrawal_validator_index,
                    deposit_receipts_start_index,
                    deposit_balance_to_consume,
                    exit_balance_to_consume,
                    earliest_exit_epoch,
                    consolidation_balance_to_consume,
                    earliest_consolidation_epoch,
                    pending_balance_deposits,
                    pending_partial_withdrawals,
                    pending_consolidations
                ],
                [historical_summaries]
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
        let fork_at_slot = spec.fork_name_at_slot::<E>(slot);

        Ok(map_fork_name!(
            fork_at_slot,
            Self,
            <_>::from_ssz_bytes(bytes)?
        ))
    }

    /// Prepare the partial state for storage in the KV database.
    pub fn as_kv_store_op(&self, state_root: Hash256) -> KeyValueStoreOp {
        let db_key = get_key_for_col(DBColumn::BeaconState.into(), state_root.as_bytes());
        KeyValueStoreOp::PutKeyValue(db_key, self.as_ssz_bytes())
    }

    pub fn load_block_roots<S: KeyValueStore<E>>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.block_roots().is_none() {
            *self.block_roots_mut() = Some(load_vector_from_db::<BlockRoots, E, _>(
                store,
                self.slot(),
                spec,
            )?);
        }
        Ok(())
    }

    pub fn load_state_roots<S: KeyValueStore<E>>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.state_roots().is_none() {
            *self.state_roots_mut() = Some(load_vector_from_db::<StateRoots, E, _>(
                store,
                self.slot(),
                spec,
            )?);
        }
        Ok(())
    }

    pub fn load_historical_roots<S: KeyValueStore<E>>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.historical_roots().is_none() {
            *self.historical_roots_mut() = Some(
                load_variable_list_from_db::<HistoricalRoots, E, _>(store, self.slot(), spec)?,
            );
        }
        Ok(())
    }

    pub fn load_historical_summaries<S: KeyValueStore<E>>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let slot = self.slot();
        if let Ok(historical_summaries) = self.historical_summaries_mut() {
            if historical_summaries.is_none() {
                *historical_summaries =
                    Some(load_variable_list_from_db::<HistoricalSummaries, E, _>(
                        store, slot, spec,
                    )?);
            }
        }
        Ok(())
    }

    pub fn load_randao_mixes<S: KeyValueStore<E>>(
        &mut self,
        store: &S,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if self.randao_mixes().is_none() {
            // Load the per-epoch values from the database
            let mut randao_mixes =
                load_vector_from_db::<RandaoMixes, E, _>(store, self.slot(), spec)?;

            // Patch the value for the current slot into the index for the current epoch
            let current_epoch = self.slot().epoch(E::slots_per_epoch());
            let len = randao_mixes.len();
            *randao_mixes
                .get_mut(current_epoch.as_usize() % len)
                .ok_or(Error::RandaoMixOutOfBounds)? = *self.latest_randao_value();

            *self.randao_mixes_mut() = Some(randao_mixes)
        }
        Ok(())
    }
}

/// Implement the conversion from PartialBeaconState -> BeaconState.
macro_rules! impl_try_into_beacon_state {
    ($inner:ident, $variant_name:ident, $struct_name:ident, [$($extra_fields:ident),*], [$($extra_opt_fields:ident),*]) => {
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
            progressive_balances_cache: <_>::default(),
            committee_caches: <_>::default(),
            pubkey_cache: <_>::default(),
            exit_cache: <_>::default(),
            slashings_cache: <_>::default(),
            epoch_cache: <_>::default(),

            // Variant-specific fields
            $(
                $extra_fields: $inner.$extra_fields
            ),*,

            // Variant-specific optional fields
            $(
                $extra_opt_fields: unpack_field($inner.$extra_opt_fields)?
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
                [previous_epoch_attestations, current_epoch_attestations],
                []
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
                ],
                []
            ),
            PartialBeaconState::Bellatrix(inner) => impl_try_into_beacon_state!(
                inner,
                Bellatrix,
                BeaconStateBellatrix,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header
                ],
                []
            ),
            PartialBeaconState::Capella(inner) => impl_try_into_beacon_state!(
                inner,
                Capella,
                BeaconStateCapella,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header,
                    next_withdrawal_index,
                    next_withdrawal_validator_index
                ],
                [historical_summaries]
            ),
            PartialBeaconState::Deneb(inner) => impl_try_into_beacon_state!(
                inner,
                Deneb,
                BeaconStateDeneb,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header,
                    next_withdrawal_index,
                    next_withdrawal_validator_index
                ],
                [historical_summaries]
            ),
            PartialBeaconState::Electra(inner) => impl_try_into_beacon_state!(
                inner,
                Electra,
                BeaconStateElectra,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header,
                    next_withdrawal_index,
                    next_withdrawal_validator_index,
                    deposit_receipts_start_index,
                    deposit_balance_to_consume,
                    exit_balance_to_consume,
                    earliest_exit_epoch,
                    consolidation_balance_to_consume,
                    earliest_consolidation_epoch,
                    pending_balance_deposits,
                    pending_partial_withdrawals,
                    pending_consolidations
                ],
                [historical_summaries]
            ),
        };
        Ok(state)
    }
}
