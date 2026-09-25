use super::*;
use crate::process_light_client_store_force_update;

impl Fixture {
    pub(super) fn force(&mut self, current_slot: u64) -> Result<(), LightClientSyncError> {
        process_light_client_store_force_update(
            &mut self.store,
            Slot::new(current_slot),
            &self.spec,
        )
    }
}

#[test]
fn empty_cache_and_unexpired_timeout_leave_every_field_unchanged() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        let initial = format!("{:?}", fixture.store);
        fixture.force(u64::MAX).unwrap();
        assert_eq!(format!("{:?}", fixture.store), initial);
        fixture.process_with_participants(1, false);
        let before = format!("{:?}", fixture.store);
        // Minimal preset: finalized slot 1 + timeout 64. Equality is not a timeout.
        for slot in [0, 1, 64, 65] {
            fixture.force(slot).unwrap();
            assert_eq!(format!("{:?}", fixture.store), before);
        }
        fixture.force(66).unwrap();
        assert_eq!(finalized_slot(&fixture.store), 2);
        assert!(fixture.store.best_valid_update().is_none());
        let after = format!("{:?}", fixture.store);
        fixture.force(u64::MAX).unwrap();
        assert_eq!(format!("{:?}", fixture.store), after);
    }
}

#[test]
fn forced_minority_finality_does_not_authenticate_checkpoint() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        let checkpoint = fixture.store.verified_checkpoint_header().clone();
        fixture.process_with_participants(1, false);
        let original = fixture.update.clone();
        let finalized = UpdateView::new(&original).finalized_header;
        fixture.force(66).unwrap();
        assert_eq!(fixture.store.spec_finalized_header(), &finalized);
        assert_eq!(optimistic_slot(&fixture.store), 3);
        assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);
        assert_eq!(fixture.store.current_max_active_participants(), 1);
        assert_eq!(fixture.store.previous_max_active_participants(), 0);
        assert_eq!(
            fixture.store.next_sync_committee(),
            Some(committee(&fixture.next_keys).as_ref())
        );
        assert_eq!(fixture.update, original);
    }
}

#[test]
fn absent_or_stale_finality_promotes_attested_data_only_in_spec_state() {
    for fork in FORKS {
        for finality in [false, true] {
            let spec = fork.make_genesis_spec(E::default_spec());
            let mut fixture = Fixture::at_slots(fork, spec, 3, 3, 5, 6);
            if !finality {
                fixture.omit_finality();
            }
            fixture.refresh_proofs(finality, true);
            fixture.process_with_participants(1, false);
            let original = fixture.update.clone();
            let attested = UpdateView::new(&original).attested_header;
            let checkpoint = fixture.store.verified_checkpoint_header().clone();
            fixture.force(68).unwrap();
            assert_eq!(fixture.store.spec_finalized_header(), &attested);
            assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);
            assert_eq!(fixture.update, original);
            assert!(fixture.store.best_valid_update().is_none());
        }
    }
}

#[test]
fn force_applies_best_candidate_not_latest_and_keeps_newer_optimistic_header() {
    let mut fixture = Fixture::new(ForkName::Altair);
    fixture.omit_finality();
    fixture.refresh_proofs(false, true);
    fixture.process_with_participants(5, false);
    let best = fixture.update.clone();
    fixture.set_slots(0, 5, 6);
    fixture.refresh_proofs(false, true);
    fixture.process_with_participants(3, false);
    assert_eq!(fixture.store.best_valid_update(), Some(&best));
    fixture.force(66).unwrap();
    assert_eq!(finalized_slot(&fixture.store), 3);
    assert_eq!(optimistic_slot(&fixture.store), 5);
    assert_eq!(fixture.store.current_max_active_participants(), 5);
    assert_eq!(
        fixture.store.verified_checkpoint_header().slot(),
        Slot::new(1)
    );
}

#[test]
fn force_can_rotate_spec_committees_and_raise_optimistic_header_without_checkpoint() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        fixture.process().unwrap();
        let checkpoint = fixture.store.verified_checkpoint_header().clone();
        fixture.set_slots(64, 65, 66);
        with_update!(&mut fixture.update, inner, {
            inner.next_sync_committee = committee(&fixture.current_keys);
        });
        fixture.refresh_proofs(true, true);
        fixture.process_with_participants(1, true);
        assert_eq!(optimistic_slot(&fixture.store), 3);
        fixture.force(67).unwrap();
        assert_eq!(finalized_slot(&fixture.store), 64);
        assert_eq!(optimistic_slot(&fixture.store), 64);
        assert_eq!(
            fixture.store.current_sync_committee(),
            committee(&fixture.next_keys).as_ref()
        );
        assert_eq!(
            fixture.store.next_sync_committee(),
            Some(committee(&fixture.current_keys).as_ref())
        );
        assert_eq!(fixture.store.previous_max_active_participants(), 32);
        assert_eq!(fixture.store.current_max_active_participants(), 0);
        assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);

        // The already authenticated p1 committee remains trusted after force rotation.
        fixture.set_slots(65, 66, 67);
        fixture.refresh_proofs(true, true);
        fixture.process_with_participants(32, true);
        assert_eq!(
            fixture.store.verified_checkpoint_header().slot(),
            Slot::new(65)
        );
    }
}

#[test]
fn force_learned_committee_cannot_launder_checkpoint_trust_through_later_supermajorities() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        let checkpoint = fixture.store.verified_checkpoint_header().clone();
        fixture.process_with_participants(1, false);
        fixture.force(66).unwrap();
        // The signature validates under p1's force-learned keys, but those keys are not trusted.
        // Even a proof for the SAME committee, signed at a period boundary, cannot certify itself.
        fixture.set_slots(3, 63, 64);
        fixture.refresh_proofs(true, true);
        fixture.process_with_participants(32, true);
        assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);

        fixture.set_slots(64, 65, 66);
        with_update!(&mut fixture.update, inner, {
            inner.next_sync_committee = committee(&fixture.current_keys);
        });
        fixture.refresh_proofs(true, true);
        fixture.process_with_participants(32, true);
        assert_eq!(finalized_slot(&fixture.store), 64);
        assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);

        // Nor can the next committee chosen by that unauthenticated chain restore trust.
        fixture.set_slots(128, 129, 130);
        with_update!(&mut fixture.update, inner, {
            inner.next_sync_committee = committee(&fixture.next_keys);
        });
        fixture.refresh_proofs(true, true);
        fixture.process_with_participants(32, false);
        assert_eq!(finalized_slot(&fixture.store), 128);
        assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);
    }
}

#[test]
fn trusted_committee_can_independently_confirm_force_learned_next_committee() {
    let mut fixture = Fixture::new(ForkName::Electra);
    fixture.process_with_participants(1, false);
    fixture.force(66).unwrap();
    assert_eq!(finalized_slot(&fixture.store), 2);
    assert_eq!(
        fixture.store.verified_checkpoint_header().slot(),
        Slot::new(1)
    );
    // No spec-finalized advancement is necessary to restore authenticated finality.
    fixture.process_with_participants(32, false);
    assert_eq!(finalized_slot(&fixture.store), 2);
    assert_eq!(
        fixture.store.verified_checkpoint_header().slot(),
        Slot::new(2)
    );
    fixture.set_slots(64, 65, 66);
    with_update!(&mut fixture.update, inner, {
        inner.next_sync_committee = committee(&fixture.current_keys);
    });
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(32, true);
    assert_eq!(
        fixture.store.verified_checkpoint_header().slot(),
        Slot::new(64)
    );
}

#[test]
fn timeout_uses_the_configured_committee_period() {
    let mut spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    spec.epochs_per_sync_committee_period = Epoch::new(2);
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 1, 2, 3, 4);
    fixture.process_with_participants(1, false);
    let before = format!("{:?}", fixture.store);
    fixture.force(17).unwrap();
    assert_eq!(format!("{:?}", fixture.store), before);
    fixture.force(18).unwrap();
    assert_eq!(finalized_slot(&fixture.store), 2);
}

#[test]
fn timeout_near_maximum_slot_does_not_overflow_or_fire_early() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(
        ForkName::Altair,
        spec,
        u64::MAX - 10,
        u64::MAX - 9,
        u64::MAX - 8,
        u64::MAX - 7,
    );
    fixture.process_with_participants(1, false);
    let before = format!("{:?}", fixture.store);
    fixture.force(u64::MAX).unwrap();
    assert_eq!(format!("{:?}", fixture.store), before);
}

#[test]
fn arithmetic_errors_preserve_cached_update_and_all_store_fields() {
    for (period, error) in [
        (0, ArithError::DivisionByZero),
        (u64::MAX, ArithError::Overflow),
    ] {
        let mut fixture = Fixture::new(ForkName::Altair);
        fixture.process_with_participants(1, false);
        let before = format!("{:?}", fixture.store);
        fixture.spec.epochs_per_sync_committee_period = Epoch::new(period);
        assert_eq!(
            fixture.force(66),
            Err(LightClientSyncError::Arithmetic(error))
        );
        assert_eq!(format!("{:?}", fixture.store), before);
    }
}
