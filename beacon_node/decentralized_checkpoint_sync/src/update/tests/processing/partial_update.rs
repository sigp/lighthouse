use super::*;
use crate::{process_light_client_finality_update, process_light_client_optimistic_update};
use types::{
    LightClientFinalityUpdate, LightClientFinalityUpdateAltair, LightClientFinalityUpdateCapella,
    LightClientFinalityUpdateDeneb, LightClientFinalityUpdateElectra,
    LightClientFinalityUpdateFulu, LightClientOptimisticUpdate, LightClientOptimisticUpdateAltair,
    LightClientOptimisticUpdateCapella, LightClientOptimisticUpdateDeneb,
    LightClientOptimisticUpdateElectra, LightClientOptimisticUpdateFulu,
};

impl Fixture {
    fn finality_update(&self) -> LightClientFinalityUpdate<E> {
        macro_rules! partial {
            ($inner:ident, $variant:ident, $type:ident) => {
                LightClientFinalityUpdate::$variant($type {
                    attested_header: $inner.attested_header.clone(),
                    finalized_header: $inner.finalized_header.clone(),
                    finality_branch: $inner.finality_branch.clone(),
                    sync_aggregate: $inner.sync_aggregate.clone(),
                    signature_slot: $inner.signature_slot,
                })
            };
        }
        match &self.update {
            LightClientUpdate::Altair(inner) => {
                partial!(inner, Altair, LightClientFinalityUpdateAltair)
            }
            LightClientUpdate::Capella(inner) => {
                partial!(inner, Capella, LightClientFinalityUpdateCapella)
            }
            LightClientUpdate::Deneb(inner) => {
                partial!(inner, Deneb, LightClientFinalityUpdateDeneb)
            }
            LightClientUpdate::Electra(inner) => {
                partial!(inner, Electra, LightClientFinalityUpdateElectra)
            }
            LightClientUpdate::Fulu(inner) => partial!(inner, Fulu, LightClientFinalityUpdateFulu),
        }
    }

    fn optimistic_update(&self) -> LightClientOptimisticUpdate<E> {
        macro_rules! partial {
            ($inner:ident, $variant:ident, $type:ident) => {
                LightClientOptimisticUpdate::$variant($type {
                    attested_header: $inner.attested_header.clone(),
                    sync_aggregate: $inner.sync_aggregate.clone(),
                    signature_slot: $inner.signature_slot,
                })
            };
        }
        match &self.update {
            LightClientUpdate::Altair(inner) => {
                partial!(inner, Altair, LightClientOptimisticUpdateAltair)
            }
            LightClientUpdate::Capella(inner) => {
                partial!(inner, Capella, LightClientOptimisticUpdateCapella)
            }
            LightClientUpdate::Deneb(inner) => {
                partial!(inner, Deneb, LightClientOptimisticUpdateDeneb)
            }
            LightClientUpdate::Electra(inner) => {
                partial!(inner, Electra, LightClientOptimisticUpdateElectra)
            }
            LightClientUpdate::Fulu(inner) => {
                partial!(inner, Fulu, LightClientOptimisticUpdateFulu)
            }
        }
    }

    fn process_partial(&mut self, finality: bool) -> Result<(), LightClientSyncError> {
        if finality {
            let update = self.finality_update();
            let before = update.clone();
            let result = process_light_client_finality_update(
                &mut self.store,
                &update,
                self.data_fork,
                self.current_slot,
                self.genesis_root,
                &self.spec,
            );
            assert_eq!(update, before);
            result
        } else {
            let update = self.optimistic_update();
            let before = update.clone();
            let result = process_light_client_optimistic_update(
                &mut self.store,
                &update,
                self.data_fork,
                self.current_slot,
                self.genesis_root,
                &self.spec,
            );
            assert_eq!(update, before);
            result
        }
    }

    fn assert_partial_error(&mut self, finality: bool, error: LightClientSyncError) {
        let before = format!("{:?}", self.store);
        assert_eq!(self.process_partial(finality), Err(error));
        assert_eq!(format!("{:?}", self.store), before);
    }
}

#[test]
fn partial_updates_match_normalized_full_updates_for_every_fork_and_participation_level() {
    for fork in FORKS {
        for count in [1, 21, 22, 32] {
            for finality in [false, true] {
                let mut partial = Fixture::new(fork);
                partial.sign_indices(&(0..count).collect::<Vec<_>>(), false);
                let mut full = Fixture::new(fork);
                full.update = partial.update.clone();
                full.omit_next_committee();
                with_update!(
                    &mut full.update,
                    inner,
                    inner.next_sync_committee_branch = Default::default()
                );
                if !finality {
                    full.omit_finality();
                    with_update!(
                        &mut full.update,
                        inner,
                        inner.finality_branch = Default::default()
                    );
                }
                // Preserve the signed attested root and proofs: only absent wire fields change.
                full.process().unwrap();
                partial.process_partial(finality).unwrap();
                assert_eq!(format!("{:?}", partial.store), format!("{:?}", full.store));
                assert_eq!(optimistic_slot(&partial.store), 3);
                assert!(partial.store.next_sync_committee().is_none());
                let expected_finalized = if finality && count >= 22 { 2 } else { 1 };
                assert_eq!(finalized_slot(&partial.store), expected_finalized);
                assert_eq!(
                    partial.store.verified_checkpoint_header().slot(),
                    Slot::new(expected_finalized)
                );
            }
        }
    }
}

#[test]
fn partial_update_errors_never_mutate_store() {
    for finality in [false, true] {
        let mut fixture = Fixture::new(ForkName::Electra);
        fixture.process_with_participants(1, false);
        with_update!(&mut fixture.update, inner, {
            inner.sync_aggregate.sync_committee_signature = AggregateSignature::infinity();
        });
        fixture.assert_partial_error(
            finality,
            LightClientSyncError::InvalidSyncCommitteeSignature,
        );
        fixture.sign_all(false);
        fixture.genesis_root = hash(120);
        fixture.assert_partial_error(
            finality,
            LightClientSyncError::InvalidSyncCommitteeSignature,
        );
        fixture.genesis_root = hash(92);
        fixture.current_slot = Slot::new(3);
        fixture.assert_partial_error(
            finality,
            LightClientSyncError::InvalidUpdateSlots {
                current_slot: Slot::new(3),
                signature_slot: Slot::new(4),
                attested_slot: Slot::new(3),
                finalized_slot: Slot::new(if finality { 2 } else { 0 }),
            },
        );
        fixture.current_slot = Slot::new(4);
        fixture.data_fork = ForkName::Gloas;
        fixture.assert_partial_error(
            finality,
            LightClientSyncError::UnsupportedFork(ForkName::Gloas),
        );
        fixture.data_fork = ForkName::Fulu;
        fixture.assert_partial_error(
            finality,
            LightClientSyncError::HeaderVariantMismatch {
                expected: ForkName::Fulu,
                actual: ForkName::Electra,
            },
        );
    }
}

#[test]
fn finality_adapter_preserves_and_validates_finality_and_execution_proofs() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        with_update!(
            &mut fixture.update,
            inner,
            inner.finality_branch[0] = hash(121)
        );
        fixture.assert_partial_error(true, LightClientSyncError::InvalidFinalityProof);
    }
    for finality in [false, true] {
        let mut fixture = Fixture::new(ForkName::Capella);
        let LightClientUpdate::Capella(inner) = &mut fixture.update else {
            unreachable!()
        };
        inner.attested_header.execution_branch[0] = hash(122);
        fixture.assert_partial_error(finality, LightClientSyncError::InvalidExecutionPayloadProof);
    }
    let mut fixture = Fixture::new(ForkName::Capella);
    let LightClientUpdate::Capella(inner) = &mut fixture.update else {
        unreachable!()
    };
    inner.finalized_header.execution_branch[0] = hash(123);
    fixture.assert_partial_error(true, LightClientSyncError::InvalidExecutionPayloadProof);
}

#[test]
fn finality_adapter_keeps_normalized_historical_branches_and_slot_fork() {
    let spec = ForkName::Capella.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(ForkName::Electra, spec, 1, 2, 3, 4);
    fixture.process_partial(true).unwrap();
    assert_eq!(
        fixture.store.verified_checkpoint_header().fork(),
        ForkName::Capella
    );
    assert_eq!(
        fixture.store.verified_checkpoint_header().slot(),
        Slot::new(2)
    );
    assert!(fixture.store.next_sync_committee().is_none());
}

#[test]
fn finality_adapter_rotates_to_known_next_committee_but_does_not_invent_a_replacement() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        fixture.process().unwrap();
        fixture.set_slots(64, 65, 66);
        fixture.refresh_proofs(true, true);
        fixture.sign_all(true);
        fixture.process_partial(true).unwrap();
        assert_eq!(finalized_slot(&fixture.store), 64);
        assert_eq!(
            fixture.store.verified_checkpoint_header().slot(),
            Slot::new(64)
        );
        assert_eq!(
            fixture.store.current_sync_committee(),
            committee(&fixture.next_keys).as_ref()
        );
        assert!(fixture.store.next_sync_committee().is_none());
        assert!(fixture.store.best_valid_update().is_none());
    }
}

#[test]
fn optimistic_adapter_requires_known_signing_committee_at_period_boundary() {
    let spec = ForkName::Altair.make_genesis_spec(E::default_spec());
    let mut fixture = Fixture::at_slots(ForkName::Altair, spec, 1, 2, 63, 64);
    fixture.assert_partial_error(
        false,
        LightClientSyncError::InvalidSignaturePeriod {
            store_period: 0,
            signature_period: 1,
        },
    );
    let mut seed = Fixture::new(ForkName::Altair);
    seed.process().unwrap();
    fixture.store = seed.store;
    fixture.sign_all(true);
    fixture.process_partial(false).unwrap();
    assert_eq!(optimistic_slot(&fixture.store), 63);
    assert_eq!(finalized_slot(&fixture.store), 2);
    assert_eq!(
        fixture.store.verified_checkpoint_header().slot(),
        Slot::new(2)
    );
    assert_eq!(
        fixture.store.next_sync_committee(),
        Some(committee(&fixture.next_keys).as_ref())
    );
}

#[test]
fn forced_optimistic_update_never_becomes_a_verified_checkpoint() {
    for fork in FORKS {
        let mut fixture = Fixture::new(fork);
        fixture.process_partial(false).unwrap();
        fixture.force(66).unwrap();
        assert_eq!(finalized_slot(&fixture.store), 3);
        assert_eq!(
            fixture.store.verified_checkpoint_header().slot(),
            Slot::new(1)
        );
        assert!(fixture.store.next_sync_committee().is_none());
        assert!(fixture.store.best_valid_update().is_none());
    }
}
