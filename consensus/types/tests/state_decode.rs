use arbitrary::Arbitrary;
use ssz::Encode;
use types::*;

#[test]
fn decode_base_and_altair() {
    type E = Spec;
    let mut spec = E::default_spec();

    let mut u = types::test_utils::test_unstructured();

    let fork_epoch = Epoch::new(1);
    spec.altair_fork_epoch = Some(fork_epoch);

    let base_epoch = fork_epoch.saturating_sub(1_u64);
    let base_slot = base_epoch.end_slot(E::slots_per_epoch());
    let altair_epoch = fork_epoch;
    let altair_slot = altair_epoch.start_slot(E::slots_per_epoch());

    // BeaconStateBase
    {
        let good_base_state: BeaconState<Spec> = BeaconState::Base(BeaconStateBase {
            slot: base_slot,
            ..<_>::arbitrary(&mut u).unwrap()
        });
        // It's invalid to have a base state with a slot higher than the fork slot.
        let bad_base_state = {
            let mut bad = good_base_state.clone();
            *bad.slot_mut() = altair_slot;
            bad
        };

        assert_eq!(
            BeaconState::from_ssz_bytes(&good_base_state.as_ssz_bytes(), &spec)
                .expect("good base state can be decoded"),
            good_base_state
        );
        <BeaconState<Spec>>::from_ssz_bytes(&bad_base_state.as_ssz_bytes(), &spec)
            .expect_err("bad base state cannot be decoded");
    }

    // BeaconStateAltair
    {
        let good_altair_state: BeaconState<Spec> = BeaconState::Altair(BeaconStateAltair {
            slot: altair_slot,
            ..<_>::arbitrary(&mut u).unwrap()
        });
        // It's invalid to have an Altair state with a slot lower than the fork slot.
        let bad_altair_state = {
            let mut bad = good_altair_state.clone();
            *bad.slot_mut() = base_slot;
            bad
        };

        assert_eq!(
            BeaconState::from_ssz_bytes(&good_altair_state.as_ssz_bytes(), &spec)
                .expect("good altair state can be decoded"),
            good_altair_state
        );
        <BeaconState<Spec>>::from_ssz_bytes(&bad_altair_state.as_ssz_bytes(), &spec)
            .expect_err("bad altair state cannot be decoded");
    }
}
