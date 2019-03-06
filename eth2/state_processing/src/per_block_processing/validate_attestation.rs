use crate::errors::{AttestationInvalid as Invalid, AttestationValidationError as Error};
use ssz::TreeHash;
use types::beacon_state::helpers::*;
use types::*;

/// Validate an attestation, checking the aggregate signature.
///
/// Spec v0.4.0
pub fn validate_attestation(
    state: &BeaconState,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    validate_attestation_signature_optional(state, attestation, spec, true)
}

/// Validate an attestation, without checking the aggregate signature.
///
/// Spec v0.4.0
pub fn validate_attestation_without_signature(
    state: &BeaconState,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    validate_attestation_signature_optional(state, attestation, spec, false)
}

/// Validate an attestation, optionally checking the aggregate signature.
///
/// Spec v0.4.0
fn validate_attestation_signature_optional(
    state: &BeaconState,
    attestation: &Attestation,
    spec: &ChainSpec,
    verify_signature: bool,
) -> Result<(), Error> {
    // Verify that `attestation.data.slot >= GENESIS_SLOT`.
    verify!(
        attestation.data.slot >= spec.genesis_slot,
        Invalid::PreGenesis
    );

    // Verify that `attestation.data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot`.
    verify!(
        attestation.data.slot + spec.min_attestation_inclusion_delay <= state.slot,
        Invalid::IncludedTooEarly
    );

    // Verify that `state.slot < attestation.data.slot + SLOTS_PER_EPOCH`.
    verify!(
        state.slot < attestation.data.slot + spec.slots_per_epoch,
        Invalid::IncludedTooLate
    );

    // Verify that `attestation.data.justified_epoch` is equal to `state.justified_epoch` if
    // `slot_to_epoch(attestation.data.slot + 1) >= get_current_epoch(state) else
    // state.previous_justified_epoch`.
    if (attestation.data.slot + 1).epoch(spec.slots_per_epoch) >= state.current_epoch(spec) {
        verify!(
            attestation.data.justified_epoch == state.justified_epoch,
            Invalid::WrongJustifiedSlot
        );
    } else {
        verify!(
            attestation.data.justified_epoch == state.previous_justified_epoch,
            Invalid::WrongJustifiedSlot
        );
    }

    // Verify that `attestation.data.justified_block_root` is equal to `get_block_root(state,
    // get_epoch_start_slot(attestation.data.justified_epoch))`.
    verify!(
        attestation.data.justified_block_root
            == *state
                .get_block_root(
                    attestation
                        .data
                        .justified_epoch
                        .start_slot(spec.slots_per_epoch),
                    &spec
                )
                .ok_or(BeaconStateError::InsufficientBlockRoots)?,
        Invalid::WrongJustifiedRoot
    );

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
        (attestation.data.latest_crosslink
            == state.latest_crosslinks[attestation.data.shard as usize])
            | (state.latest_crosslinks[attestation.data.shard as usize] == potential_crosslink),
        Invalid::BadLatestCrosslinkRoot
    );

    // Get the committee for this attestation
    let (committee, _shard) = state
        .get_crosslink_committees_at_slot(attestation.data.slot, spec)?
        .iter()
        .find(|(_committee, shard)| *shard == attestation.data.shard)
        .ok_or_else(|| Error::Invalid(Invalid::NoCommitteeForShard))?;

    // Custody bitfield is all zeros (phase 0 requirement).
    verify!(
        attestation.custody_bitfield.num_set_bits() == 0,
        Invalid::CustodyBitfieldHasSetBits
    );
    // Custody bitfield length is correct.
    verify!(
        verify_bitfield_length(&attestation.aggregation_bitfield, committee.len()),
        Invalid::BadCustodyBitfieldLength
    );
    // Aggregation bitfield isn't empty.
    verify!(
        attestation.aggregation_bitfield.num_set_bits() != 0,
        Invalid::AggregationBitfieldIsEmpty
    );
    // Aggregation bitfield length is correct.
    verify!(
        verify_bitfield_length(&attestation.aggregation_bitfield, committee.len()),
        Invalid::BadAggregationBitfieldLength
    );

    if verify_signature {
        let attestation_epoch = attestation.data.slot.epoch(spec.slots_per_epoch);
        verify!(
            verify_attestation_signature(
                state,
                committee,
                attestation_epoch,
                &attestation.custody_bitfield,
                &attestation.data,
                &attestation.aggregate_signature,
                spec
            ),
            Invalid::BadSignature
        );
    }

    // [TO BE REMOVED IN PHASE 1] Verify that `attestation.data.crosslink_data_root == ZERO_HASH`.
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
/// Spec v0.4.0
fn verify_attestation_signature(
    state: &BeaconState,
    committee: &[usize],
    attestation_epoch: Epoch,
    custody_bitfield: &Bitfield,
    attestation_data: &AttestationData,
    aggregate_signature: &AggregateSignature,
    spec: &ChainSpec,
) -> bool {
    let mut aggregate_pubs = vec![AggregatePublicKey::new(); 2];
    let mut message_exists = vec![false; 2];

    for (i, v) in committee.iter().enumerate() {
        let custody_bit = match custody_bitfield.get(i) {
            Ok(bit) => bit,
            // Invalidate signature if custody_bitfield.len() < committee
            Err(_) => return false,
        };

        message_exists[custody_bit as usize] = true;

        match state.validator_registry.get(*v as usize) {
            Some(validator) => {
                aggregate_pubs[custody_bit as usize].add(&validator.pubkey);
            }
            // Invalidate signature if validator index is unknown.
            None => return false,
        };
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

    aggregate_signature.verify_multiple(&messages[..], domain, &keys[..])
}
