use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, validator_monitor::get_slot_delay_ms,
};

use slot_clock::{SlotClock, timestamp_now};
use std::time::Duration;
use strum::AsRefStr;
use tree_hash::TreeHash;
use types::{Domain, EthSpec, SignedInclusionList, SignedRoot, Slot};

#[derive(Debug, AsRefStr)]
pub enum GossipInclusionListError {
    InvalidSlot {
        message_slot: Slot,
        current_slot: Slot,
    },
    InvalidCommitteeRoot,
    ValidatorNotInCommittee,
    TooManyTransactions,
    InvalidSignature,
    BeaconChainError(Box<BeaconChainError>),
    PriorInclusionListKnown,
}

impl From<BeaconChainError> for GossipInclusionListError {
    fn from(value: BeaconChainError) -> Self {
        Self::BeaconChainError(value.into())
    }
}

pub struct GossipVerifiedInclusionList<T: BeaconChainTypes> {
    pub signed_il: SignedInclusionList<T::EthSpec>,
    pub is_timely: bool,
}

impl<T: BeaconChainTypes> GossipVerifiedInclusionList<T> {
    pub fn verify(
        signed_il: &SignedInclusionList<T::EthSpec>,
        chain: &BeaconChain<T>,
        seen_timestamp: Option<Duration>,
    ) -> Result<Self, GossipInclusionListError> {
        let message_slot = signed_il.message.slot;

        let current_slot = chain
            .slot_clock
            .now()
            .ok_or(BeaconChainError::UnableToReadSlot)?;

        if signed_il
            .message
            .transactions
            .iter()
            .map(|v| v.len())
            .sum::<usize>()
            > chain.spec.max_bytes_per_inclusion_list as usize
        {
            return Err(GossipInclusionListError::TooManyTransactions);
        }

        // [IGNORE] The slot `message.slot` is equal to the current slot
        // (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance)
        let earliest_permissible_slot = chain
            .slot_clock
            .now_with_past_tolerance(chain.spec.maximum_gossip_clock_disparity())
            .ok_or(BeaconChainError::UnableToReadSlot)?;
        let latest_permissible_slot = chain
            .slot_clock
            .now_with_future_tolerance(chain.spec.maximum_gossip_clock_disparity())
            .ok_or(BeaconChainError::UnableToReadSlot)?;
        if message_slot < earliest_permissible_slot || message_slot > latest_permissible_slot {
            return Err(GossipInclusionListError::InvalidSlot {
                message_slot,
                current_slot,
            });
        }

        let head_snapshot = chain.head_snapshot();

        let il_committee = head_snapshot
            .beacon_state
            .get_inclusion_list_committee(message_slot, &chain.spec)
            .map_err(|_| GossipInclusionListError::InvalidCommitteeRoot)?;

        if signed_il.message.inclusion_list_committee_root != il_committee.tree_hash_root() {
            return Err(GossipInclusionListError::InvalidCommitteeRoot);
        }

        if !il_committee.contains(&signed_il.message.validator_index) {
            return Err(GossipInclusionListError::ValidatorNotInCommittee);
        }

        // The signature is valid w.r.t. the validator index, using the domain at the
        // epoch of `message.slot` per `is_valid_inclusion_list_signature`.
        let epoch = message_slot.epoch(T::EthSpec::slots_per_epoch());
        let fork = chain.spec.fork_at_epoch(epoch);
        let genesis_validators_root = chain.genesis_validators_root;
        let domain = chain.spec.get_domain(
            epoch,
            Domain::InclusionListCommittee,
            &fork,
            genesis_validators_root,
        );
        let message = signed_il.message.signing_root(domain);
        let validator_index = signed_il.message.validator_index as usize;
        let pubkey = chain.validator_pubkey(validator_index)?;
        let Some(pubkey) = pubkey else {
            return Err(GossipInclusionListError::BeaconChainError(Box::new(
                BeaconChainError::ValidatorIndexUnknown(validator_index),
            )));
        };

        if !signed_il.signature.verify(&pubkey, message) {
            return Err(GossipInclusionListError::InvalidSignature);
        }

        // [IGNORE] The message is either the first or second valid message received from the
        // validator. A second, distinct message is admitted so equivocation evidence is
        // forwarded and recorded; duplicates and third-or-later messages are ignored.
        if chain.inclusion_list_seen(signed_il) {
            return Err(GossipInclusionListError::PriorInclusionListKnown);
        }

        let slot_duration_ms = chain.spec.get_slot_duration().as_millis() as u64;
        let inclusion_list_due_ms = slot_duration_ms * chain.spec.inclusion_list_due_bps / 10000;
        // Timeliness is measured from when the message was received, not when this
        // verification runs, so processor queueing delay cannot mark a timely IL late.
        let il_delay_ms = get_slot_delay_ms(
            seen_timestamp.unwrap_or_else(timestamp_now),
            message_slot,
            &chain.slot_clock,
        )
        .as_millis() as u64;
        let is_timely = il_delay_ms < inclusion_list_due_ms;

        Ok(Self {
            signed_il: signed_il.clone(),
            is_timely,
        })
    }
}
