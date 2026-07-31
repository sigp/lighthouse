use state_processing::per_slot_processing;
use types::*;

type E = MinimalEthSpec;

fn genesis_state(n: usize) -> (BeaconState<E>, ChainSpec) {
    let spec = E::default_spec();
    let mut state = BeaconState::new(0, Default::default(), &spec);
    for _ in 0..n {
        state
            .validators_mut()
            .push(Validator {
                effective_balance: spec.max_effective_balance,
                activation_epoch: Epoch::new(0),
                exit_epoch: spec.far_future_epoch,
                withdrawable_epoch: spec.far_future_epoch,
                ..Default::default()
            })
            .expect("push validator");
        state
            .balances_mut()
            .push(spec.max_effective_balance)
            .expect("push balance");
    }
    state
        .build_all_committee_caches(&spec)
        .expect("committee caches");
    (state, spec)
}

fn advance_state(state: &mut BeaconState<E>, target: Slot, spec: &ChainSpec) {
    while state.slot() < target {
        per_slot_processing(state, None, spec).expect("advance slot");
    }
    state
        .build_all_committee_caches(spec)
        .expect("committee caches");
}

#[test]
fn builds_from_genesis_state() {
    let (state, spec) = genesis_state(64);
    SlotAssignments::new::<E>(&state, &spec, None).expect("builds from genesis state");
}

#[test]
fn every_validator_attests_once_in_current_epoch() {
    let (mut state, spec) = genesis_state(64);
    let spe = E::slots_per_epoch();
    let start = Slot::new(spe * 2);
    advance_state(&mut state, start, &spec);
    let sa = SlotAssignments::new::<E>(&state, &spec, None).expect("build");

    let end = Slot::new(spe * 2 + spe - 1);
    for val_idx in 0..state.validators().len() {
        assert!(
            sa.is_in_range(val_idx, start, end).unwrap(),
            "validator {val_idx} missing epoch 2 assignment"
        );
    }
}

// Test that in the `restore_from_store` path a state loaded from disk has no
// committee caches built, and building slot assignments from it must not fail.
#[test]
fn builds_from_state_with_unbuilt_caches() {
    let (mut state, spec) = genesis_state(64);
    let spe = E::slots_per_epoch();
    advance_state(&mut state, Slot::new(spe * 2), &spec);
    let control = SlotAssignments::new::<E>(&state, &spec, None).expect("build with caches");

    state.drop_all_caches().expect("drop caches");
    let rebuilt = SlotAssignments::new::<E>(&state, &spec, None)
        .expect("builds when committee caches are uninitialized");

    for val_idx in 0..state.validators().len() {
        for slot in 0..spe * 3 {
            let slot = Slot::new(slot);
            assert_eq!(
                control.is_in_range(val_idx, slot, slot).unwrap(),
                rebuilt.is_in_range(val_idx, slot, slot).unwrap(),
                "validator {val_idx} assignment mismatch at slot {slot}"
            );
        }
    }
}

#[test]
fn is_in_range_returns_false_for_uncovered_epochs() {
    let (state, spec) = genesis_state(64);
    let sa = SlotAssignments::new::<E>(&state, &spec, None).expect("build");
    let far = Slot::new(E::slots_per_epoch() * 5);
    for val_idx in 0..state.validators().len() {
        assert!(!sa.is_in_range(val_idx, far, far).unwrap());
    }
}
