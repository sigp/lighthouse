use crate::{
    beacon_chain::MAXIMUM_GOSSIP_CLOCK_DISPARITY,
    observed_attestations::{Error as AttestationObservationError, ObserveOutcome},
    BeaconChain, BeaconChainError, BeaconChainTypes,
};
use slot_clock::SlotClock;
use tree_hash::TreeHash;
use types::{Attestation, EthSpec, Slot};

pub enum Error {
    /// The attestation is from a slot that is later than the current slot (with respect to the
    /// gossip clock disparity).
    FutureSlot {
        attestation_slot: Slot,
        latest_permissible_slot: Slot,
    },
    /// The attestation is from a slot that is prior to the earliest permissible slolt (with
    /// respect to the gossip clock disparity).
    PastSlot {
        attestation_slot: Slot,
        earliest_permissible_slot: Slot,
    },
    /// The attestation has been seen before; either in a block, on the gossip network or from a
    /// local validator.
    AttestationAlreadyKnown,
    /// There was an error whilst processing the attestation. It is not known if it is valid or invalid.
    BeaconChainError(BeaconChainError),
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChainError(e)
    }
}

#[derive(Debug, PartialEq)]
pub enum AttestationType {
    /// An attestation with a single-signature that has been published in accordance with the naive
    /// aggregation strategy.
    ///
    /// These attestations may have come from a `committee_index{subnet_id}_beacon_attestation`
    /// gossip subnet or they have have come directly from a validator attached to our API.
    ///
    /// If `should_store == true`, the attestation will be added to the `NaiveAggregationPool`.
    Unaggregated { should_store: bool },
    /// An attestation with one more more signatures that has passed through the aggregation phase
    /// of the naive aggregation scheme.
    ///
    /// These attestations must have come from the `beacon_aggregate_and_proof` gossip subnet.
    Aggregated,
}

pub struct GossipVerifiedAttestation<T: BeaconChainTypes> {
    attestation: Attestation<T::EthSpec>,
    attestation_type: AttestationType,
}

pub struct FullyVerifiedAttestation<T: BeaconChainTypes> {
    attestation: Attestation<T::EthSpec>,
    attestation_type: AttestationType,
}

impl<T: BeaconChainTypes> GossipVerifiedAttestation<T> {
    pub fn new(
        attestation: Attestation<T::EthSpec>,
        attestation_type: AttestationType,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        let attestation_slot = attestation.data.slot;

        let latest_permissible_slot = chain
            .slot_clock
            .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
            .ok_or_else(|| BeaconChainError::UnableToReadSlot)?;
        if attestation_slot > latest_permissible_slot {
            return Err(Error::FutureSlot {
                attestation_slot,
                latest_permissible_slot,
            });
        }

        // Taking advantage of saturating subtraction on `Slot`.
        let earliest_permissible_slot = chain
            .slot_clock
            .now_with_past_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
            .ok_or_else(|| BeaconChainError::UnableToReadSlot)?
            - T::EthSpec::slots_per_epoch();
        if attestation_slot < earliest_permissible_slot {
            return Err(Error::PastSlot {
                attestation_slot,
                earliest_permissible_slot,
            });
        }

        let attestation_root = attestation.tree_hash_root();

        if let ObserveOutcome::AlreadyKnown = chain
            .observed_attestations
            .observe(&attestation, Some(attestation_root))
            .map_err(|e| Error::BeaconChainError(e.into()))?
        {
            return Err(Error::AttestationAlreadyKnown);
        }

        /*
        The aggregate is the first valid aggregate received for the aggregator with index
        aggregate_and_proof.aggregator_index for the slot aggregate.data.slot.
        */

        /*
        The block being voted for (aggregate.data.beacon_block_root) passes validation.
        */

        /*
        aggregate_and_proof.selection_proof selects the validator as an aggregator for the slot --
        i.e. is_aggregator(state, aggregate.data.slot, aggregate.data.index,
            aggregate_and_proof.selection_proof) returns True.
        */

        /*
        The aggregator's validator index is within the aggregate's committee -- i.e.
        aggregate_and_proof.aggregator_index in get_attesting_indices(state, aggregate.data,
            aggregate.aggregation_bits).
        */

        /*
        The aggregate_and_proof.selection_proof is a valid signature of the aggregate.data.slot by
        the validator with index aggregate_and_proof.aggregator_index.
        */

        /*
        The aggregator signature, signed_aggregate_and_proof.signature, is valid.
        */

        /*
        The signature of aggregate is valid.
        */

        todo!();
    }
}
