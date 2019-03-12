#![cfg(test)]

use super::*;
use crate::test_utils::TestingBeaconStateBuilder;
use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
use crate::{BeaconState, ChainSpec};
use ssz::{ssz_encode, Decodable};

/// Tests that `get_attestation_participants` is consistent with the result of
/// get_crosslink_committees_at_slot` with a full bitfield.
#[test]
pub fn get_attestation_participants_consistency() {
    let mut rng = XorShiftRng::from_seed([42; 16]);

    let spec = ChainSpec::few_validators();
    let builder = TestingBeaconStateBuilder::from_deterministic_keypairs(8, &spec);
    let (mut state, _keypairs) = builder.build();

    state
        .build_epoch_cache(RelativeEpoch::Previous, &spec)
        .unwrap();
    state
        .build_epoch_cache(RelativeEpoch::Current, &spec)
        .unwrap();
    state.build_epoch_cache(RelativeEpoch::Next, &spec).unwrap();

    for slot in state
        .slot
        .epoch(spec.slots_per_epoch)
        .slot_iter(spec.slots_per_epoch)
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

#[test]
pub fn test_ssz_round_trip() {
    let mut rng = XorShiftRng::from_seed([42; 16]);
    let original = BeaconState::random_for_test(&mut rng);

    let bytes = ssz_encode(&original);
    let (decoded, _) = <_>::ssz_decode(&bytes, 0).unwrap();

    assert_eq!(original, decoded);
}

#[test]
pub fn test_hash_tree_root_internal() {
    let mut rng = XorShiftRng::from_seed([42; 16]);
    let original = BeaconState::random_for_test(&mut rng);

    let result = original.hash_tree_root_internal();

    assert_eq!(result.len(), 32);
    // TODO: Add further tests
    // https://github.com/sigp/lighthouse/issues/170
}
