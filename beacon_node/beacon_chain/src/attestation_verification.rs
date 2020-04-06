use crate::{
    beacon_chain::{
        ATTESTATION_CACHE_LOCK_TIMEOUT, HEAD_LOCK_TIMEOUT, MAXIMUM_GOSSIP_CLOCK_DISPARITY,
        VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT,
    },
    metrics,
    observed_attestations::{Error as AttestationObservationError, ObserveOutcome},
    BeaconChain, BeaconChainError, BeaconChainTypes,
};
use slog::debug;
use slot_clock::SlotClock;
use state_processing::{
    common::get_indexed_attestation, per_block_processing::errors::AttestationValidationError,
    per_slot_processing, signature_sets::indexed_attestation_signature_set_from_pubkeys,
};
use std::borrow::Cow;
use tree_hash::TreeHash;
use types::{
    Attestation, CommitteeIndex, EthSpec, Hash256, IndexedAttestation, RelativeEpoch, Slot,
};

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
    /// The `attestation.data.beacon_block_root` block is unknown.
    UnknownHeadBlock {
        beacon_block_root: Hash256,
    },
    BadTargetEpoch,
    UnknownTargetRoot(Hash256),
    InvalidSignature,
    NoCommitteeForSlotAndIndex {
        slot: Slot,
        index: CommitteeIndex,
    },
    NotExactlyOneAggregationBitSet(usize),
    Invalid(AttestationValidationError),
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
    attestation_root: Hash256,
}

pub struct FullyVerifiedAttestation<T: BeaconChainTypes> {
    attestation: Attestation<T::EthSpec>,
    attestation_type: AttestationType,
}

// TODO: aggregates:
//
/*
The aggregate is the first valid aggregate received for the aggregator with index
aggregate_and_proof.aggregator_index for the slot aggregate.data.slot.
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
       let attestation_root = attestation.tree_hash_root();

       if let ObserveOutcome::AlreadyKnown = chain
           .observed_attestations
           .observe_attestation(&attestation, Some(attestation_root))
           .map_err(|e| Error::BeaconChainError(e.into()))?
       {
           return Err(Error::AttestationAlreadyKnown);
       }
*/

impl<T: BeaconChainTypes> GossipVerifiedAttestation<T> {
    pub fn new(
        attestation: Attestation<T::EthSpec>,
        attestation_type: AttestationType,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        // Ensure attestation is within the last ATTESTATION_PROPAGATION_SLOT_RANGE slots (within a
        // MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance).
        //
        // We do not queue future attestations for later processing.
        verify_propagation_slot_range(chain, &attestation)?;

        // Check to ensure that the attestation is "unaggregated". I.e., it has exactly one
        // aggregation bit set.
        let num_aggreagtion_bits = attestation.aggregation_bits.num_set_bits();
        if num_aggreagtion_bits != 1 {
            return Err(Error::NotExactlyOneAggregationBitSet(num_aggreagtion_bits));
        }

        /*
         * The attestation is the first valid attestation received for the participating validator
         * for the slot, attestation.data.slot.
         *
         * TODO!!
         */
        let attestation_root = attestation.data.tree_hash_root();

        // The block being voted for (attestation.data.beacon_block_root) passes validation.
        //
        // This indirectly checks to see if the `attestation.data.beacon_block_root` is in our fork
        // choice. Any known, non-finalized, processed block should be in fork choice, so this
        // check immediately filters out attestations that attest to a block that has not been
        // processed.
        //
        // Attestations must be for a known block. If the block is unknown, we simply drop the
        // attestation and do not delay consideration for later.
        let (block_slot, _state_root) = chain
            .fork_choice
            .block_slot_and_state_root(&attestation.data.beacon_block_root)
            .ok_or_else(|| Error::UnknownHeadBlock {
                beacon_block_root: attestation.data.beacon_block_root,
            })?;

        let indexed_attestation = obtain_indexed_attestation(chain, &attestation, block_slot)?;

        // The signature of attestation is valid.
        verify_attestation_signature(chain, &indexed_attestation, block_slot)?;

        Ok(Self {
            attestation,
            attestation_type,
            attestation_root,
        })
    }
}

pub fn verify_propagation_slot_range<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    attestation: &Attestation<T::EthSpec>,
) -> Result<(), Error> {
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

    Ok(())
}

pub fn verify_attestation_signature<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    indexed_attestation: &IndexedAttestation<T::EthSpec>,
    block_slot: Slot,
) -> Result<(), Error> {
    let signature_setup_timer =
        metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_SETUP_TIMES);

    let pubkey_cache = chain
        .validator_pubkey_cache
        .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
        .ok_or_else(|| BeaconChainError::ValidatorPubkeyCacheLockTimeout)?;

    let fork = chain
        .canonical_head
        .try_read_for(HEAD_LOCK_TIMEOUT)
        .ok_or_else(|| BeaconChainError::CanonicalHeadLockTimeout)
        .map(|head| head.beacon_state.fork.clone())?;

    let signature_set = indexed_attestation_signature_set_from_pubkeys(
        |validator_index| {
            pubkey_cache
                .get(validator_index)
                .map(|pk| Cow::Borrowed(pk.as_point()))
        },
        &indexed_attestation.signature,
        &indexed_attestation,
        &fork,
        &chain.spec,
    )
    .map_err(BeaconChainError::SignatureSetError)?;

    metrics::stop_timer(signature_setup_timer);

    let _signature_verification_timer =
        metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_TIMES);

    if signature_set.is_valid() {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

pub fn obtain_indexed_attestation<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    attestation: &Attestation<T::EthSpec>,
    block_slot: Slot,
) -> Result<IndexedAttestation<T::EthSpec>, Error> {
    let attestation_epoch = attestation.data.slot.epoch(T::EthSpec::slots_per_epoch());
    let target = &attestation.data.target;

    // Attestation target must be for a known block.
    //
    // We use fork choice to find the target root, which means that we reject any attestation
    // that has a `target.root` earlier than our latest finalized root. There's no point in
    // processing an attestation that does not include our latest finalized block in its chain.
    //
    // We do not delay consideration for later, we simply drop the attestation.
    //
    // TODO: make sure this isn't too strict....
    let (target_block_slot, target_block_state_root) = chain
        .fork_choice
        .block_slot_and_state_root(&target.root)
        .ok_or_else(|| Error::UnknownTargetRoot(target.root))?;

    let cache_wait_timer =
        metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SHUFFLING_CACHE_WAIT_TIMES);

    let mut shuffling_cache = chain
        .shuffling_cache
        .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
        .ok_or_else(|| BeaconChainError::AttestationCacheLockTimeout)?;

    metrics::stop_timer(cache_wait_timer);
    if let Some(committee_cache) = shuffling_cache.get(attestation_epoch, target.root) {
        committee_cache
            .get_beacon_committee(attestation.data.slot, attestation.data.index)
            .map(|committee| {
                get_indexed_attestation(committee.committee, &attestation)
                    .map_err(|e| BeaconChainError::from(e).into())
            })
            .unwrap_or_else(|| {
                Err(Error::NoCommitteeForSlotAndIndex {
                    slot: attestation.data.slot,
                    index: attestation.data.index,
                })
            })
    } else {
        // Drop the shuffling cache to avoid holding the lock for any longer than
        // required.
        drop(shuffling_cache);

        debug!(
            chain.log,
            "Attestation processing cache miss";
            "attn_epoch" => attestation_epoch.as_u64(),
            "head_block_epoch" => block_slot.epoch(T::EthSpec::slots_per_epoch()).as_u64(),
        );

        let state_read_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_STATE_READ_TIMES);

        let mut state = chain
            .get_state(&target_block_state_root, Some(target_block_slot))?
            .ok_or_else(|| BeaconChainError::MissingBeaconState(target_block_state_root))?;

        metrics::stop_timer(state_read_timer);
        let state_skip_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_STATE_SKIP_TIMES);

        while state.current_epoch() + 1 < attestation_epoch {
            // Here we tell `per_slot_processing` to skip hashing the state and just
            // use the zero hash instead.
            //
            // The state roots are not useful for the shuffling, so there's no need to
            // compute them.
            per_slot_processing(&mut state, Some(Hash256::zero()), &chain.spec)
                .map_err(|e| BeaconChainError::from(e))?
        }

        metrics::stop_timer(state_skip_timer);
        let committee_building_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_COMMITTEE_BUILDING_TIMES);

        let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), attestation_epoch)
            .map_err(BeaconChainError::IncorrectStateForAttestation)?;

        state
            .build_committee_cache(relative_epoch, &chain.spec)
            .map_err(|e| BeaconChainError::from(e))?;

        let committee_cache = state
            .committee_cache(relative_epoch)
            .map_err(|e| BeaconChainError::from(e))?;

        chain
            .shuffling_cache
            .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
            .ok_or_else(|| BeaconChainError::AttestationCacheLockTimeout)?
            .insert(attestation_epoch, target.root, committee_cache);

        metrics::stop_timer(committee_building_timer);

        committee_cache
            .get_beacon_committee(attestation.data.slot, attestation.data.index)
            .map(|committee| {
                get_indexed_attestation(committee.committee, &attestation)
                    .map_err(|e| BeaconChainError::from(e).into())
            })
            .unwrap_or_else(|| {
                Err(Error::NoCommitteeForSlotAndIndex {
                    slot: attestation.data.slot,
                    index: attestation.data.index,
                })
            })
    }
}
