use std::time::Duration;

use crate::{
    validator_monitor::{get_slot_delay_ms, timestamp_now},
    BeaconChain, BeaconChainError, BeaconChainTypes,
};

use slot_clock::SlotClock;
use strum::AsRefStr;
use tree_hash::TreeHash;
use types::{Domain, SignedInclusionList, SignedRoot, Slot};

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
    InclusionListSeen,
    // TODO: equivocation e.g. PriorInclusionListKnown
}

impl From<BeaconChainError> for GossipInclusionListError {
    fn from(value: BeaconChainError) -> Self {
        Self::BeaconChainError(value.into())
    }
}

pub struct GossipVerifiedInclusionList<T: BeaconChainTypes> {
    pub signed_il: SignedInclusionList<T::EthSpec>,
}

impl<T: BeaconChainTypes> GossipVerifiedInclusionList<T> {
    pub fn verify(
        signed_il: &SignedInclusionList<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, GossipInclusionListError> {
        // the slot is equal to the previous slot or the current slot
        let message_slot = signed_il.message.slot;

        let current_slot = chain
            .slot_clock
            .now()
            .ok_or(BeaconChainError::UnableToReadSlot)?;

        // TODO(focil) move 8192 to config
        if signed_il
            .message
            .transactions
            .iter()
            .map(|v| v.len())
            .sum::<usize>()
            > 8192
        {
            return Err(GossipInclusionListError::TooManyTransactions);
        }

        if message_slot != current_slot && message_slot != current_slot - 1 {
            return Err(GossipInclusionListError::InvalidSlot {
                message_slot,
                current_slot,
            });
        }

        let attestation_deadline = Duration::from_secs(chain.spec.seconds_per_slot / 3);

        let inclusion_list_delay_total =
            get_slot_delay_ms(timestamp_now(), message_slot, &chain.slot_clock);

        let exceeds_attestation_deadline = attestation_deadline >= inclusion_list_delay_total;

        if exceeds_attestation_deadline {
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
            tracing::error!("INVALID COMMITTEE ROOT");
            return Err(GossipInclusionListError::InvalidCommitteeRoot);
        }

        if !il_committee.contains(&signed_il.message.validator_index) {
            return Err(GossipInclusionListError::ValidatorNotInCommittee);
        }

        // the signature is valid w.r.t. the validator index
        let epoch = chain.epoch()?;
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

        if chain.inclusion_list_seen(&signed_il) {
            return Err(GossipInclusionListError::InclusionListSeen);
        }

        Ok(Self {
            signed_il: signed_il.clone(),
        })
    }
}
