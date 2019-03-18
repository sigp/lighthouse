use super::errors::{AttestationInvalid as Invalid, AttestationValidationError as Error};
use ssz::TreeHash;
use types::beacon_state::helpers::*;
use types::*;

/// Indicates if an `Attestation` is valid to be included in a block in the current epoch of the
/// given state.
///
/// Returns `Ok(())` if the `Attestation` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.5.0
pub fn validate_attestation(
    state: &BeaconState,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    validate_attestation_signature_optional(state, attestation, spec, true)
}

/// Indicates if an `Attestation` is valid to be included in a block in the current epoch of the
/// given state, without validating the aggregate signature.
///
/// Returns `Ok(())` if the `Attestation` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.5.0
pub fn validate_attestation_without_signature(
    state: &BeaconState,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    validate_attestation_signature_optional(state, attestation, spec, false)
}

/// Indicates if an `Attestation` is valid to be included in a block in the current epoch of the
/// given state, optionally validating the aggregate signature.
///
///
/// Spec v0.5.0
fn validate_attestation_signature_optional(
    state: &BeaconState,
    attestation: &Attestation,
    spec: &ChainSpec,
    verify_signature: bool,
) -> Result<(), Error> {
    let state_epoch = state.slot.epoch(spec.slots_per_epoch);
    let attestation_epoch = attestation.data.slot.epoch(spec.slots_per_epoch);

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
        attestation.data.slot + spec.min_attestation_inclusion_delay <= state.slot,
        Invalid::IncludedTooEarly {
            state: state.slot,
            delay: spec.min_attestation_inclusion_delay,
            attestation: attestation.data.slot
        }
    );

    // Verify the justified epoch and root is correct.
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
        let attestation_epoch = attestation.data.slot.epoch(spec.slots_per_epoch);
        verify_attestation_signature(
            state,
            committee,
            attestation_epoch,
            &attestation.aggregation_bitfield,
            &attestation.custody_bitfield,
            &attestation.data,
            &attestation.aggregate_signature,
            spec,
        )?;
    }

    // Crosslink data root is zero (to be removed in phase 1).
    verify!(
        attestation.data.crosslink_data_root == spec.zero_hash,
        Invalid::ShardBlockRootNotZero
    );

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
/// Spec v0.5.0
fn verify_attestation_signature(
    state: &BeaconState,
    committee: &[usize],
    attestation_epoch: Epoch,
    aggregation_bitfield: &Bitfield,
    custody_bitfield: &Bitfield,
    attestation_data: &AttestationData,
    aggregate_signature: &AggregateSignature,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let mut aggregate_pubs = vec![AggregatePublicKey::new(); 2];
    let mut message_exists = vec![false; 2];

    for (i, v) in committee.iter().enumerate() {
        let validator_signed = aggregation_bitfield.get(i).map_err(|_| {
            Error::Invalid(Invalid::BadAggregationBitfieldLength {
                committee_len: committee.len(),
                bitfield_len: aggregation_bitfield.len(),
            })
        })?;

        if validator_signed {
            let custody_bit: bool = match custody_bitfield.get(i) {
                Ok(bit) => bit,
                // Invalidate signature if custody_bitfield.len() < committee
                Err(_) => {
                    return Err(Error::Invalid(Invalid::BadCustodyBitfieldLength {
                        committee_len: committee.len(),
                        bitfield_len: aggregation_bitfield.len(),
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
        data: attestation_data.clone(),
        custody_bit: false,
    }
    .hash_tree_root();

    // Message when custody bitfield is `true`
    let message_1 = AttestationDataAndCustodyBit {
        data: attestation_data.clone(),
        custody_bit: true,
    }
    .hash_tree_root();

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
        aggregate_signature.verify_multiple(&messages[..], domain, &keys[..]),
        Invalid::BadSignature
    );

    Ok(())
}
