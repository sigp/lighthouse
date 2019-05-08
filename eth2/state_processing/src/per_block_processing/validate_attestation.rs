use super::errors::{AttestationInvalid as Invalid, AttestationValidationError as Error};
use crate::common::verify_bitfield_length;
use tree_hash::TreeHash;
use types::*;

/// Indicates if an `Attestation` is valid to be included in a block in the current epoch of the
/// given state.
///
/// Returns `Ok(())` if the `Attestation` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.5.1
pub fn validate_attestation<T: BeaconStateTypes>(
    state: &BeaconState<T>,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    validate_attestation_parametric(state, attestation, spec, true, false)
}

/// Like `validate_attestation` but doesn't run checks which may become true in future states.
pub fn validate_attestation_time_independent_only<T: BeaconStateTypes>(
    state: &BeaconState<T>,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    validate_attestation_parametric(state, attestation, spec, true, true)
}

/// Indicates if an `Attestation` is valid to be included in a block in the current epoch of the
/// given state, without validating the aggregate signature.
///
/// Returns `Ok(())` if the `Attestation` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.5.1
pub fn validate_attestation_without_signature<T: BeaconStateTypes>(
    state: &BeaconState<T>,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    validate_attestation_parametric(state, attestation, spec, false, false)
}

/// Indicates if an `Attestation` is valid to be included in a block in the current epoch of the
/// given state, optionally validating the aggregate signature.
///
///
/// Spec v0.5.1
fn validate_attestation_parametric<T: BeaconStateTypes>(
    state: &BeaconState<T>,
    attestation: &Attestation,
    spec: &ChainSpec,
    verify_signature: bool,
    time_independent_only: bool,
) -> Result<(), Error> {
    // Can't submit pre-historic attestations.
    verify!(
        attestation.data.slot >= spec.genesis_slot,
        Invalid::PreGenesis {
            genesis: spec.genesis_slot,
            attestation: attestation.data.slot
        }
    );

    // Can't submit attestations too far in history.
    verify!(
        state.slot <= attestation.data.slot + spec.slots_per_epoch,
        Invalid::IncludedTooLate {
            state: spec.genesis_slot,
            attestation: attestation.data.slot
        }
    );

    // Can't submit attestation too quickly.
    verify!(
        time_independent_only
            || attestation.data.slot + spec.min_attestation_inclusion_delay <= state.slot,
        Invalid::IncludedTooEarly {
            state: state.slot,
            delay: spec.min_attestation_inclusion_delay,
            attestation: attestation.data.slot
        }
    );

    // Verify the justified epoch and root is correct.
    if !time_independent_only {
        verify_justified_epoch_and_root(attestation, state, spec)?;
    }

    // Check that the crosslink data is valid.
    //
    // Verify that either:
    //
    // (i)`state.latest_crosslinks[attestation.data.shard] == attestation.data.latest_crosslink`,
    //
    // (ii) `state.latest_crosslinks[attestation.data.shard] ==
    // Crosslink(crosslink_data_root=attestation.data.crosslink_data_root,
    // epoch=slot_to_epoch(attestation.data.slot))`.
    let potential_crosslink = Crosslink {
        crosslink_data_root: attestation.data.crosslink_data_root,
        epoch: attestation.data.slot.epoch(spec.slots_per_epoch),
    };
    verify!(
        (attestation.data.previous_crosslink
            == state.latest_crosslinks[attestation.data.shard as usize])
            | (state.latest_crosslinks[attestation.data.shard as usize] == potential_crosslink),
        Invalid::BadPreviousCrosslink
    );

    // Attestation must be non-empty!
    verify!(
        attestation.aggregation_bitfield.num_set_bits() != 0,
        Invalid::AggregationBitfieldIsEmpty
    );
    // Custody bitfield must be empty (be be removed in phase 1)
    verify!(
        attestation.custody_bitfield.num_set_bits() == 0,
        Invalid::CustodyBitfieldHasSetBits
    );

    // Get the committee for the specific shard that this attestation is for.
    let crosslink_committee = state
        .get_crosslink_committees_at_slot(attestation.data.slot, spec)?
        .iter()
        .find(|c| c.shard == attestation.data.shard)
        .ok_or_else(|| {
            Error::Invalid(Invalid::NoCommitteeForShard {
                shard: attestation.data.shard,
                slot: attestation.data.slot,
            })
        })?;
    let committee = &crosslink_committee.committee;

    // Custody bitfield length is correct.
    //
    // This is not directly in the spec, but it is inferred.
    verify!(
        verify_bitfield_length(&attestation.custody_bitfield, committee.len()),
        Invalid::BadCustodyBitfieldLength {
            committee_len: committee.len(),
            bitfield_len: attestation.custody_bitfield.len()
        }
    );
    // Aggregation bitfield length is correct.
    //
    // This is not directly in the spec, but it is inferred.
    verify!(
        verify_bitfield_length(&attestation.aggregation_bitfield, committee.len()),
        Invalid::BadAggregationBitfieldLength {
            committee_len: committee.len(),
            bitfield_len: attestation.custody_bitfield.len()
        }
    );

    if verify_signature {
        verify_attestation_signature(state, committee, attestation, spec)?;
    }

    // Crosslink data root is zero (to be removed in phase 1).
    verify!(
        attestation.data.crosslink_data_root == spec.zero_hash,
        Invalid::ShardBlockRootNotZero
    );

    Ok(())
}

/// Verify that the `source_epoch` and `source_root` of an `Attestation` correctly
/// match the current (or previous) justified epoch and root from the state.
///
/// Spec v0.5.1
fn verify_justified_epoch_and_root<T: BeaconStateTypes>(
    attestation: &Attestation,
    state: &BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let state_epoch = state.slot.epoch(spec.slots_per_epoch);
    let attestation_epoch = attestation.data.slot.epoch(spec.slots_per_epoch);

    if attestation_epoch >= state_epoch {
        verify!(
            attestation.data.source_epoch == state.current_justified_epoch,
            Invalid::WrongJustifiedEpoch {
                state: state.current_justified_epoch,
                attestation: attestation.data.source_epoch,
                is_current: true,
            }
        );
        verify!(
            attestation.data.source_root == state.current_justified_root,
            Invalid::WrongJustifiedRoot {
                state: state.current_justified_root,
                attestation: attestation.data.source_root,
                is_current: true,
            }
        );
    } else {
        verify!(
            attestation.data.source_epoch == state.previous_justified_epoch,
            Invalid::WrongJustifiedEpoch {
                state: state.previous_justified_epoch,
                attestation: attestation.data.source_epoch,
                is_current: false,
            }
        );
        verify!(
            attestation.data.source_root == state.previous_justified_root,
            Invalid::WrongJustifiedRoot {
                state: state.previous_justified_root,
                attestation: attestation.data.source_root,
                is_current: true,
            }
        );
    }
    Ok(())
}

/// Verifies an aggregate signature for some given `AttestationData`, returning `true` if the
/// `aggregate_signature` is valid.
///
/// Returns `false` if:
///  - `aggregate_signature` was not signed correctly.
///  - `custody_bitfield` does not have a bit for each index of `committee`.
///  - A `validator_index` in `committee` is not in `state.validator_registry`.
///
/// Spec v0.5.1
fn verify_attestation_signature<T: BeaconStateTypes>(
    state: &BeaconState<T>,
    committee: &[usize],
    a: &Attestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let mut aggregate_pubs = vec![AggregatePublicKey::new(); 2];
    let mut message_exists = vec![false; 2];
    let attestation_epoch = a.data.slot.epoch(spec.slots_per_epoch);

    for (i, v) in committee.iter().enumerate() {
        let validator_signed = a.aggregation_bitfield.get(i).map_err(|_| {
            Error::Invalid(Invalid::BadAggregationBitfieldLength {
                committee_len: committee.len(),
                bitfield_len: a.aggregation_bitfield.len(),
            })
        })?;

        if validator_signed {
            let custody_bit: bool = match a.custody_bitfield.get(i) {
                Ok(bit) => bit,
                // Invalidate signature if custody_bitfield.len() < committee
                Err(_) => {
                    return Err(Error::Invalid(Invalid::BadCustodyBitfieldLength {
                        committee_len: committee.len(),
                        bitfield_len: a.aggregation_bitfield.len(),
                    }));
                }
            };

            message_exists[custody_bit as usize] = true;

            match state.validator_registry.get(*v as usize) {
                Some(validator) => {
                    aggregate_pubs[custody_bit as usize].add(&validator.pubkey);
                }
                // Return error if validator index is unknown.
                None => return Err(Error::BeaconStateError(BeaconStateError::UnknownValidator)),
            };
        }
    }

    // Message when custody bitfield is `false`
    let message_0 = AttestationDataAndCustodyBit {
        data: a.data.clone(),
        custody_bit: false,
    }
    .tree_hash_root();

    // Message when custody bitfield is `true`
    let message_1 = AttestationDataAndCustodyBit {
        data: a.data.clone(),
        custody_bit: true,
    }
    .tree_hash_root();

    let mut messages = vec![];
    let mut keys = vec![];

    // If any validator signed a message with a `false` custody bit.
    if message_exists[0] {
        messages.push(&message_0[..]);
        keys.push(&aggregate_pubs[0]);
    }
    // If any validator signed a message with a `true` custody bit.
    if message_exists[1] {
        messages.push(&message_1[..]);
        keys.push(&aggregate_pubs[1]);
    }

    let domain = spec.get_domain(attestation_epoch, Domain::Attestation, &state.fork);

    verify!(
        a.aggregate_signature
            .verify_multiple(&messages[..], domain, &keys[..]),
        Invalid::BadSignature
    );

    Ok(())
}
