#![cfg(test)]

use super::*;
use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
use crate::{BeaconState, ChainSpec};

#[test]
pub fn can_produce_genesis_block() {
    let mut builder = BeaconStateBuilder::new(2);
    builder.build().unwrap();
}

/// Tests that `get_attestation_participants` is consistent with the result of
/// get_crosslink_committees_at_slot` with a full bitfield.
#[test]
pub fn get_attestation_participants_consistency() {
    let mut rng = XorShiftRng::from_seed([42; 16]);

    let mut builder = BeaconStateBuilder::new(8);
    builder.spec = ChainSpec::few_validators();

    builder.build().unwrap();

    let mut state = builder.cloned_state();
    let spec = builder.spec.clone();

    state
        .build_epoch_cache(RelativeEpoch::Previous, &spec)
        .unwrap();
    state
        .build_epoch_cache(RelativeEpoch::Current, &spec)
        .unwrap();
    state.build_epoch_cache(RelativeEpoch::Next, &spec).unwrap();

    for slot in state
        .slot
        .epoch(spec.epoch_length)
        .slot_iter(spec.epoch_length)
    {
        let committees = state.get_crosslink_committees_at_slot(slot, &spec).unwrap();

        for (committee, shard) in committees {
            let mut attestation_data = AttestationData::random_for_test(&mut rng);
            attestation_data.slot = slot;
            attestation_data.shard = *shard;

            let mut bitfield = Bitfield::new();
            for (i, _) in committee.iter().enumerate() {
                bitfield.set(i, true);
            }

            assert_eq!(
                state
                    .get_attestation_participants(&attestation_data, &bitfield, &spec)
                    .unwrap(),
                *committee
            );
        }
    }
}

ssz_tests!(BeaconState);
