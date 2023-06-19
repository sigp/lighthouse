use crate::{
    BeaconState, BeaconStateAltair, BeaconStateBase, BeaconStateCapella, BeaconStateError as Error,
    BeaconStateMerge, EthSpec, PublicKeyBytes, VList, Validator, ValidatorMutable,
};
use itertools::process_results;
use std::sync::Arc;

pub type CompactBeaconState<E> = BeaconState<E, ValidatorMutable>;

/// Implement the conversion function from BeaconState -> CompactBeaconState.
macro_rules! full_to_compact {
    ($s:ident, $outer:ident, $variant_name:ident, $struct_name:ident, [$($extra_fields:ident),*]) => {
        BeaconState::$variant_name($struct_name {
            // Versioning
            genesis_time: $s.genesis_time,
            genesis_validators_root: $s.genesis_validators_root,
            slot: $s.slot,
            fork: $s.fork,

            // History
            latest_block_header: $s.latest_block_header.clone(),
            block_roots: $s.block_roots.clone(),
            state_roots: $s.state_roots.clone(),
            historical_roots: $s.historical_roots.clone(),

            // Eth1
            eth1_data: $s.eth1_data.clone(),
            eth1_data_votes: $s.eth1_data_votes.clone(),
            eth1_deposit_index: $s.eth1_deposit_index,

            // Validator registry
            validators: VList::try_from_iter(
                $s.validators.into_iter().map(|validator| validator.mutable.clone())
            ).expect("fix this"),
            balances: $s.balances.clone(),

            // Shuffling
            randao_mixes: $s.randao_mixes.clone(),

            // Slashings
            slashings: $s.slashings.clone(),

            // Finality
            justification_bits: $s.justification_bits.clone(),
            previous_justified_checkpoint: $s.previous_justified_checkpoint,
            current_justified_checkpoint: $s.current_justified_checkpoint,
            finalized_checkpoint: $s.finalized_checkpoint,

            // Caches.
            total_active_balance: $s.total_active_balance.clone(),
            committee_caches: $s.committee_caches.clone(),
            pubkey_cache: $s.pubkey_cache.clone(),
            exit_cache: $s.exit_cache.clone(),

            // Variant-specific fields
            $(
                $extra_fields: $s.$extra_fields.clone()
            ),*
        })
    }
}

/// Implement the conversion from CompactBeaconState -> BeaconState.
macro_rules! compact_to_full {
    ($inner:ident, $variant_name:ident, $struct_name:ident, $immutable_validators:ident, [$($extra_fields:ident),*]) => {
        BeaconState::$variant_name($struct_name {
            // Versioning
            genesis_time: $inner.genesis_time,
            genesis_validators_root: $inner.genesis_validators_root,
            slot: $inner.slot,
            fork: $inner.fork,

            // History
            latest_block_header: $inner.latest_block_header,
            block_roots: $inner.block_roots,
            state_roots: $inner.state_roots,
            historical_roots: $inner.historical_roots,

            // Eth1
            eth1_data: $inner.eth1_data,
            eth1_data_votes: $inner.eth1_data_votes,
            eth1_deposit_index: $inner.eth1_deposit_index,

            // Validator registry
            validators: process_results($inner.validators.into_iter().enumerate().map(|(i, mutable)| {
                $immutable_validators(i)
                    .ok_or(Error::MissingImmutableValidator(i))
                    .map(move |pubkey| {
                        Validator {
                            pubkey,
                            mutable: mutable.clone(),
                        }
                    })
            }), |iter| VList::try_from_iter(iter))??,
            balances: $inner.balances,

            // Shuffling
            randao_mixes: $inner.randao_mixes,

            // Slashings
            slashings: $inner.slashings,

            // Finality
            justification_bits: $inner.justification_bits,
            previous_justified_checkpoint: $inner.previous_justified_checkpoint,
            current_justified_checkpoint: $inner.current_justified_checkpoint,
            finalized_checkpoint: $inner.finalized_checkpoint,

            // Caching
            total_active_balance: $inner.total_active_balance,
            committee_caches: $inner.committee_caches,
            pubkey_cache: $inner.pubkey_cache,
            exit_cache: $inner.exit_cache,

            // Variant-specific fields
            $(
                $extra_fields: $inner.$extra_fields
            ),*
        })
    }
}

impl<E: EthSpec> BeaconState<E> {
    pub fn into_compact_state(self) -> CompactBeaconState<E> {
        match self {
            BeaconState::Base(s) => full_to_compact!(
                s,
                self,
                Base,
                BeaconStateBase,
                [previous_epoch_attestations, current_epoch_attestations]
            ),
            BeaconState::Altair(s) => full_to_compact!(
                s,
                self,
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
            BeaconState::Merge(s) => full_to_compact!(
                s,
                self,
                Merge,
                BeaconStateMerge,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header
                ]
            ),
            BeaconState::Capella(s) => full_to_compact!(
                s,
                self,
                Capella,
                BeaconStateCapella,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header,
                    historical_summaries,
                    next_withdrawal_index,
                    next_withdrawal_validator_index
                ]
            ),
        }
    }
}

impl<E: EthSpec> CompactBeaconState<E> {
    pub fn try_into_full_state<F>(self, immutable_validators: F) -> Result<BeaconState<E>, Error>
    where
        F: Fn(usize) -> Option<Arc<PublicKeyBytes>>,
    {
        let state = match self {
            BeaconState::Base(inner) => compact_to_full!(
                inner,
                Base,
                BeaconStateBase,
                immutable_validators,
                [previous_epoch_attestations, current_epoch_attestations]
            ),
            BeaconState::Altair(inner) => compact_to_full!(
                inner,
                Altair,
                BeaconStateAltair,
                immutable_validators,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores
                ]
            ),
            BeaconState::Merge(inner) => compact_to_full!(
                inner,
                Merge,
                BeaconStateMerge,
                immutable_validators,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header
                ]
            ),
            BeaconState::Capella(inner) => compact_to_full!(
                inner,
                Capella,
                BeaconStateCapella,
                immutable_validators,
                [
                    previous_epoch_participation,
                    current_epoch_participation,
                    current_sync_committee,
                    next_sync_committee,
                    inactivity_scores,
                    latest_execution_payload_header,
                    historical_summaries,
                    next_withdrawal_index,
                    next_withdrawal_validator_index
                ]
            ),
        };
        Ok(state)
    }
}
