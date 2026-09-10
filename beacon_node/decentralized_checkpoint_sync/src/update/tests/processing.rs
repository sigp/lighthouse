use super::*;
use crate::process_light_client_update;

mod force_update;
mod partial_update;

impl Fixture {
    fn process(&mut self) -> Result<(), LightClientSyncError> {
        validate_light_client_update(
            &mut self.store,
            &self.update,
            self.data_fork,
            self.current_slot,
            self.genesis_root,
            &self.spec,
        )
        .and_then(process_light_client_update)
    }

    fn process_with_participants(&mut self, count: usize, next: bool) {
        self.sign_indices(&(0..count).collect::<Vec<_>>(), next);
        self.process().unwrap();
    }

    fn set_slots(&mut self, finalized: u64, attested: u64, signature: u64) {
        with_update!(&mut self.update, inner, {
            inner.finalized_header.beacon.slot = Slot::new(finalized);
            inner.attested_header.beacon.slot = Slot::new(attested);
            inner.signature_slot = Slot::new(signature);
        });
        self.current_slot = Slot::new(signature);
    }

    fn omit_finality(&mut self) {
        with_update!(
            &mut self.update,
            inner,
            inner.finalized_header = Default::default()
        );
    }

    fn omit_next_committee(&mut self) {
        with_update!(&mut self.update, inner, {
            inner.next_sync_committee = Arc::new(SyncCommittee::temporary());
        });
    }

    fn assert_process_error(&mut self, expected: LightClientSyncError) {
        let before = format!("{:?}", self.store);
        assert_eq!(self.process(), Err(expected));
        assert_eq!(format!("{:?}", self.store), before);
    }
}

fn finalized_slot(store: &LightClientStore<E>) -> u64 {
    beacon_header(store.spec_finalized_header()).slot.as_u64()
}

fn optimistic_slot(store: &LightClientStore<E>) -> u64 {
    beacon_header(store.optimistic_header()).slot.as_u64()
}

#[test]
fn supermajority_finality_advances_store_and_checkpoint_for_every_fork() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        let finalized = UpdateView::new(&fixture.update).finalized_header;
        fixture.process().unwrap();
        assert_eq!(finalized_slot(&fixture.store), 2);
        assert_eq!(optimistic_slot(&fixture.store), 3);
        assert_eq!(
            fixture.store.current_sync_committee(),
            committee(&fixture.current_keys).as_ref()
        );
        assert_eq!(
            fixture.store.next_sync_committee(),
            Some(committee(&fixture.next_keys).as_ref())
        );
        assert_eq!(fixture.store.current_max_active_participants(), 32);
        assert_eq!(fixture.store.previous_max_active_participants(), 0);
        assert_eq!(fixture.store.safety_threshold(), 16);
        assert!(fixture.store.best_valid_update().is_none());
        let checkpoint = fixture.store.verified_checkpoint_header();
        assert_eq!(checkpoint.header(), &finalized);
        assert_eq!(
            checkpoint.beacon_block_root(),
            beacon_header(&finalized).canonical_root()
        );
        assert_eq!(
            checkpoint.beacon_state_root(),
            beacon_header(&finalized).state_root
        );
        assert_eq!(checkpoint.fork(), fork);
    }
}

#[test]
fn finality_requires_two_thirds_of_the_entire_committee_not_observed_participants() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        let checkpoint = fixture.store.verified_checkpoint_header().clone();
        fixture.process_with_participants(21, false);
        assert_eq!(finalized_slot(&fixture.store), 1);
        assert_eq!(optimistic_slot(&fixture.store), 3);
        assert_eq!(fixture.store.safety_threshold(), 10);
        assert!(fixture.store.next_sync_committee().is_none());
        assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);
        assert_eq!(fixture.store.best_valid_update(), Some(&fixture.update));

        fixture.process_with_participants(22, false);
        assert_eq!(finalized_slot(&fixture.store), 2);
        assert_eq!(
            fixture.store.verified_checkpoint_header().slot(),
            Slot::new(2)
        );
        assert!(fixture.store.next_sync_committee().is_some());
        assert!(fixture.store.best_valid_update().is_none());
    }
}

#[test]
fn supermajority_without_finality_never_authenticates_a_checkpoint_or_committee() {
    for has_committee in [false, true] {
        let mut fixture = Fixture::new(ForkName::Electra);
        let checkpoint = fixture.store.verified_checkpoint_header().clone();
        fixture.omit_finality();
        if !has_committee {
            fixture.omit_next_committee();
        }
        fixture.refresh_proofs(false, has_committee);
        fixture.process_with_participants(32, false);
        assert_eq!(finalized_slot(&fixture.store), 1);
        assert_eq!(optimistic_slot(&fixture.store), 3);
        assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);
        assert!(fixture.store.next_sync_committee().is_none());
        assert_eq!(fixture.store.best_valid_update(), Some(&fixture.update));
    }
}

#[test]
fn learns_finalized_next_committee_without_advancing_finalized_slot() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 3, 3, 4, 5);
    let checkpoint = fixture.store.verified_checkpoint_header().clone();
    fixture.process().unwrap();
    assert_eq!(finalized_slot(&fixture.store), 3);
    assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);
    assert!(fixture.store.next_sync_committee().is_some());
    assert!(fixture.store.best_valid_update().is_none());
    // Once the committee is known, the same update no longer causes an apply or cache clear.
    fixture.process().unwrap();
    assert_eq!(fixture.store.best_valid_update(), Some(&fixture.update));
}

#[test]
fn optimistic_threshold_is_strict_and_headers_never_regress() {
    let mut fixture = Fixture::new(ForkName::Altair);
    fixture.process_with_participants(22, false);
    let checkpoint = fixture.store.verified_checkpoint_header().clone();
    fixture.set_slots(1, 5, 6);
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(11, false);
    assert_eq!(fixture.store.safety_threshold(), 11);
    assert_eq!(optimistic_slot(&fixture.store), 3);
    fixture.process_with_participants(12, false);
    assert_eq!(optimistic_slot(&fixture.store), 5);
    fixture.set_slots(1, 4, 5);
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(32, false);
    assert_eq!(optimistic_slot(&fixture.store), 5);
    assert_eq!(finalized_slot(&fixture.store), 2);
    assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);
    assert_eq!(fixture.store.current_max_active_participants(), 32);
}

#[test]
fn two_committee_rotations_use_authenticated_keys_and_carry_participation_maxima() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        fixture.process_with_participants(22, false);
        // The p0 committee authenticates p1. No test-only committee setter is used.
        fixture.set_slots(64, 65, 66);
        with_update!(&mut fixture.update, inner, {
            inner.next_sync_committee = committee(&fixture.current_keys);
        });
        fixture.refresh_proofs(true, true);
        fixture.process_with_participants(32, true);
        assert_eq!(finalized_slot(&fixture.store), 64);
        assert_eq!(optimistic_slot(&fixture.store), 65);
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
        assert_eq!(fixture.store.safety_threshold(), 16);
        assert!(fixture.store.best_valid_update().is_none());

        fixture.set_slots(64, 66, 67);
        fixture.refresh_proofs(true, true);
        fixture.process_with_participants(16, true);
        assert_eq!(optimistic_slot(&fixture.store), 65);
        fixture.process_with_participants(17, true);
        assert_eq!(optimistic_slot(&fixture.store), 66);
        assert_eq!(fixture.store.previous_max_active_participants(), 32);
        assert_eq!(fixture.store.current_max_active_participants(), 17);
        assert_eq!(
            fixture.store.verified_checkpoint_header().slot(),
            Slot::new(64)
        );

        // p1 authenticates p2, which happens to contain the original keys in this fixture.
        fixture.set_slots(128, 129, 130);
        with_update!(&mut fixture.update, inner, {
            inner.next_sync_committee = committee(&fixture.next_keys);
        });
        fixture.refresh_proofs(true, true);
        fixture.process_with_participants(22, false);
        assert_eq!(finalized_slot(&fixture.store), 128);
        assert_eq!(
            fixture.store.verified_checkpoint_header().slot(),
            Slot::new(128)
        );
        assert_eq!(
            fixture.store.current_sync_committee(),
            committee(&fixture.current_keys).as_ref()
        );
        assert_eq!(
            fixture.store.next_sync_committee(),
            Some(committee(&fixture.next_keys).as_ref())
        );
        // Previous-period history expires on rotation; it must not stay at 32 forever.
        assert_eq!(fixture.store.previous_max_active_participants(), 22);
        assert_eq!(fixture.store.current_max_active_participants(), 0);
        assert_eq!(fixture.store.safety_threshold(), 11);
    }
}

#[test]
fn finality_only_rotation_clears_next_committee_until_it_is_learned_again() {
    let mut fixture = Fixture::new(ForkName::Electra);
    fixture.process().unwrap();
    fixture.set_slots(3, 4, 5);
    fixture.omit_next_committee();
    fixture.refresh_proofs(true, false);
    fixture.process_with_participants(32, false);
    // A missing branch does not erase an already known committee within the same period.
    assert_eq!(
        fixture.store.next_sync_committee(),
        Some(committee(&fixture.next_keys).as_ref())
    );
    fixture.set_slots(64, 65, 66);
    fixture.refresh_proofs(true, false);
    fixture.process_with_participants(32, true);
    assert_eq!(
        fixture.store.current_sync_committee(),
        committee(&fixture.next_keys).as_ref()
    );
    assert!(fixture.store.next_sync_committee().is_none());
    assert_eq!(finalized_slot(&fixture.store), 64);
    fixture.set_slots(66, 67, 68);
    fixture.refresh_proofs(true, false);
    fixture.process_with_participants(22, true);
    assert_eq!(finalized_slot(&fixture.store), 66);
    assert!(fixture.store.next_sync_committee().is_none());

    fixture.set_slots(66, 127, 128);
    fixture.refresh_proofs(true, false);
    fixture.sign_all(false);
    fixture.assert_process_error(LightClientSyncError::InvalidSignaturePeriod {
        store_period: 1,
        signature_period: 2,
    });

    fixture.set_slots(66, 68, 69);
    with_update!(&mut fixture.update, inner, {
        inner.next_sync_committee = committee(&fixture.current_keys);
    });
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(22, true);
    assert_eq!(
        fixture.store.next_sync_committee(),
        Some(committee(&fixture.current_keys).as_ref())
    );
    assert!(fixture.store.best_valid_update().is_none());
    assert_eq!(finalized_slot(&fixture.store), 66);
}

#[test]
fn next_period_signatures_do_not_rotate_committees_before_finality_crosses_period() {
    let mut fixture = Fixture::new(ForkName::Altair);
    fixture.process_with_participants(22, false);
    fixture.set_slots(3, 63, 64);
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(32, true);
    assert_eq!(fixture.store.current_max_active_participants(), 32);
    assert_eq!(fixture.store.previous_max_active_participants(), 0);
    assert_eq!(finalized_slot(&fixture.store), 3);
    fixture.set_slots(4, 65, 66);
    with_update!(&mut fixture.update, inner, {
        inner.next_sync_committee = committee(&fixture.current_keys);
    });
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(32, true);
    assert_eq!(
        fixture.store.current_sync_committee(),
        committee(&fixture.current_keys).as_ref()
    );
    assert_eq!(
        fixture.store.next_sync_committee(),
        Some(committee(&fixture.next_keys).as_ref())
    );
    assert_eq!(fixture.store.current_max_active_participants(), 32);
    assert_eq!(fixture.store.previous_max_active_participants(), 0);
    assert_eq!(
        fixture.store.verified_checkpoint_header().slot(),
        Slot::new(4)
    );
}

#[test]
fn genesis_finality_and_historical_finality_do_not_replace_the_bootstrap_anchor() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        let checkpoint = fixture.store.verified_checkpoint_header().clone();
        fixture.omit_finality();
        fixture.refresh_proofs(true, true);
        fixture.process_with_participants(32, false);
        assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);
        assert_eq!(finalized_slot(&fixture.store), 1);
        assert!(fixture.store.next_sync_committee().is_some());
        assert!(fixture.store.best_valid_update().is_none());
    }
    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(Epoch::new(1));
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 8, 2, 10, 11);
    let checkpoint = fixture.store.verified_checkpoint_header().clone();
    fixture.process().unwrap();
    assert_eq!(fixture.store.verified_checkpoint_header(), &checkpoint);
    assert_eq!(finalized_slot(&fixture.store), 8);
}

#[test]
fn checkpoint_fork_comes_from_finalized_slot_not_upgraded_update_schema() {
    let spec = ForkName::Capella.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(ForkName::Electra, spec, 1, 2, 3, 4);
    fixture.process().unwrap();
    let checkpoint = fixture.store.verified_checkpoint_header();
    assert_eq!(checkpoint.fork(), ForkName::Capella);
    assert!(matches!(checkpoint.header(), LightClientHeader::Electra(_)));
    assert_eq!(checkpoint.slot(), Slot::new(2));
}

#[test]
fn default_committee_with_a_valid_branch_is_still_unknown() {
    let mut fixture = Fixture::new(ForkName::Altair);
    fixture.omit_next_committee();
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(32, false);
    assert_eq!(finalized_slot(&fixture.store), 2);
    assert!(fixture.store.next_sync_committee().is_none());
}

#[test]
fn invalid_updates_cannot_poison_best_update_participation_or_headers() {
    let mut fixture = Fixture::new(ForkName::Electra);
    fixture.process_with_participants(1, false);
    fixture.sign_all(false);
    with_update!(
        &mut fixture.update,
        inner,
        inner.finality_branch[0] = hash(110)
    );
    fixture.assert_process_error(LightClientSyncError::InvalidFinalityProof);
    fixture.refresh_proofs(true, true);
    with_update!(&mut fixture.update, inner, {
        inner.sync_aggregate.sync_committee_signature = AggregateSignature::infinity();
    });
    fixture.assert_process_error(LightClientSyncError::InvalidSyncCommitteeSignature);
    fixture.sign_all(false);
    fixture.process().unwrap();
    fixture.set_slots(1, 2, 3);
    fixture.refresh_proofs(true, true);
    fixture.sign_all(false);
    fixture.assert_process_error(LightClientSyncError::IrrelevantUpdate);
}

type RankingCase = (usize, Option<u64>, bool, u64, u64);

fn ranking_fixture((participants, finality, next, attested, signature): RankingCase) -> Fixture {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(
        ForkName::Altair,
        spec,
        64,
        finality.unwrap_or(0),
        attested,
        signature,
    );
    if finality.is_none() {
        fixture.omit_finality();
    }
    if !next {
        fixture.omit_next_committee();
    }
    fixture.refresh_proofs(finality.is_some(), next);
    fixture.sign_indices(&(0..participants).collect::<Vec<_>>(), false);
    fixture
}

fn assert_best_selection(old: RankingCase, new: RankingCase, replace: bool) {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut seed = Fixture::at_slots(ForkName::Altair, spec, 64, 64, 65, 66);
    seed.process().unwrap();
    let mut old = ranking_fixture(old);
    old.store = seed.store;
    old.process().unwrap();
    assert_eq!(old.store.best_valid_update(), Some(&old.update));
    let mut new = ranking_fixture(new);
    new.store = old.store;
    new.process().unwrap();
    let expected = if replace { &new.update } else { &old.update };
    assert_eq!(new.store.best_valid_update(), Some(expected));
    assert_eq!(finalized_slot(&new.store), 64);
    assert_eq!(new.store.verified_checkpoint_header().slot(), Slot::new(64));
}

#[test]
fn best_update_uses_existing_spec_ranking_in_the_correct_direction() {
    // Each pair lists the worse candidate first, exercising all ranking priorities through
    // real validation and processing. Finality never advances, so the cache remains observable.
    let cases = [
        ((21, Some(64), true, 66, 67), (22, None, false, 66, 67)),
        ((2, Some(64), true, 66, 67), (3, None, false, 66, 67)),
        ((32, Some(64), false, 66, 67), (22, Some(64), true, 66, 67)),
        ((32, None, true, 66, 67), (22, Some(64), true, 66, 67)),
        ((32, Some(2), true, 66, 67), (22, Some(64), true, 66, 67)),
        ((22, Some(64), true, 66, 67), (23, Some(64), true, 66, 67)),
        ((22, Some(64), true, 67, 68), (22, Some(64), true, 66, 68)),
        ((22, Some(64), true, 66, 68), (22, Some(64), true, 66, 67)),
    ];
    for (worse, better) in cases {
        assert_best_selection(worse, better, true);
        assert_best_selection(better, worse, false);
    }
    let identical = (22, Some(64), true, 66, 67);
    assert_best_selection(identical, identical, false);
}
