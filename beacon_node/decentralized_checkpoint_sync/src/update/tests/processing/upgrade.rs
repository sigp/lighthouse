use super::*;
use crate::{
    upgrade_light_client_bootstrap, upgrade_light_client_header, upgrade_light_client_store,
    upgrade_light_client_update, validate_light_client_header,
};

fn bootstrap_for(fork: ForkName, spec: &ChainSpec, keys: &[Keypair]) -> LightClientBootstrap<E> {
    let current_sync_committee = committee(keys);
    let depth = if fork.electra_enabled() { 6 } else { 5 };
    let tree = state_tree(depth, &[(22, current_sync_committee.tree_hash_root())]);
    let branch = tree.generate_proof(22, depth).unwrap().1;
    let header = header(fork, spec, Slot::new(1), tree.hash());
    macro_rules! bootstrap {
        ($inner:expr, $type:ident, $variant:ident) => {
            LightClientBootstrap::$variant($type {
                header: $inner,
                current_sync_committee,
                current_sync_committee_branch: branch.try_into().unwrap(),
            })
        };
    }
    match header {
        LightClientHeader::Altair(inner) => bootstrap!(inner, LightClientBootstrapAltair, Altair),
        LightClientHeader::Capella(inner) => {
            bootstrap!(inner, LightClientBootstrapCapella, Capella)
        }
        LightClientHeader::Deneb(inner) => bootstrap!(inner, LightClientBootstrapDeneb, Deneb),
        LightClientHeader::Electra(inner) => {
            bootstrap!(inner, LightClientBootstrapElectra, Electra)
        }
        LightClientHeader::Fulu(inner) => bootstrap!(inner, LightClientBootstrapFulu, Fulu),
    }
}

fn assert_checkpoint_preserved(
    store: &LightClientStore<E>,
    previous: &crate::VerifiedFinalizedHeader<E>,
    target: ForkName,
) {
    let checkpoint = store.verified_checkpoint_header();
    assert_eq!(
        checkpoint.header(),
        &upgrade_light_client_header(previous.header(), target).unwrap()
    );
    assert_eq!(checkpoint.beacon_block_root(), previous.beacon_block_root());
    assert_eq!(checkpoint.beacon_state_root(), previous.beacon_state_root());
    assert_eq!(checkpoint.slot(), previous.slot());
    assert_eq!(checkpoint.fork(), previous.fork());
}

#[test]
fn every_forward_upgrade_preserves_real_signatures_and_processes_without_resigning() {
    for source in FORKS {
        for target in FORKS.into_iter().filter(|fork| *fork >= source) {
            let mut fixture = Fixture::new(source);
            let original = fixture.update.clone();
            let original_view = UpdateView::new(&original);
            let original_checkpoint = fixture.store.verified_checkpoint_header().clone();
            fixture.update = upgrade_light_client_update(&original, target).unwrap();
            fixture.data_fork = target;
            upgrade_light_client_store(&mut fixture.store, target).unwrap();
            let upgraded_view = UpdateView::new(&fixture.update);
            assert_eq!(fixture.update.sync_aggregate(), original.sync_aggregate());
            assert_eq!(fixture.update.signature_slot(), original.signature_slot());
            assert!(Arc::ptr_eq(
                fixture.update.next_sync_committee(),
                original.next_sync_committee()
            ));
            assert_eq!(
                beacon_header(&upgraded_view.attested_header),
                beacon_header(&original_view.attested_header)
            );
            assert_eq!(
                beacon_header(&upgraded_view.finalized_header),
                beacon_header(&original_view.finalized_header)
            );
            assert_checkpoint_preserved(&fixture.store, &original_checkpoint, target);
            fixture.valid();
            fixture.process().unwrap();
            assert_eq!(finalized_slot(&fixture.store), 2);
            assert_eq!(optimistic_slot(&fixture.store), 3);
            assert_eq!(fixture.store.verified_checkpoint_header().fork(), source);
            assert_eq!(
                fixture.store.verified_checkpoint_header().header(),
                &upgrade_light_client_header(&original_view.finalized_header, target).unwrap()
            );
        }
    }
}

#[test]
fn bootstrap_upgrades_preserve_trusted_root_and_verify_original_committee_proof() {
    for source in FORKS {
        let fixture = Fixture::new(source);
        let original = bootstrap_for(source, &fixture.spec, &fixture.current_keys);
        let trusted_root = fixture
            .store
            .verified_checkpoint_header()
            .beacon_block_root();
        let original_copy = original.clone();
        for target in FORKS.into_iter().filter(|fork| *fork >= source) {
            let upgraded = upgrade_light_client_bootstrap(&original, target).unwrap();
            let store = initialize_light_client_store(
                trusted_root,
                &upgraded,
                target,
                LightClientStoreSchema::try_from(target).unwrap(),
                &fixture.spec,
            )
            .unwrap();
            assert_checkpoint_preserved(&store, fixture.store.verified_checkpoint_header(), target);
            assert_eq!(
                store.current_sync_committee(),
                fixture.store.current_sync_committee()
            );
            assert_eq!(
                upgrade_light_client_bootstrap(&upgraded, target).unwrap(),
                upgraded
            );
            assert_eq!(original, original_copy);
        }
    }
}

#[test]
fn direct_multifork_upgrades_equal_sequential_upgrades_and_are_idempotent() {
    let fixture = Fixture::new(ForkName::Altair);
    let original_header = fixture.store.spec_finalized_header().clone();
    let original_bootstrap = bootstrap_for(ForkName::Altair, &fixture.spec, &fixture.current_keys);
    let mut sequential_header = original_header.clone();
    let mut sequential_update = fixture.update.clone();
    let mut sequential_bootstrap = original_bootstrap.clone();
    let mut sequential_store = fixture.store;
    for target in FORKS {
        sequential_header = upgrade_light_client_header(&sequential_header, target).unwrap();
        sequential_update = upgrade_light_client_update(&sequential_update, target).unwrap();
        sequential_bootstrap =
            upgrade_light_client_bootstrap(&sequential_bootstrap, target).unwrap();
        upgrade_light_client_store(&mut sequential_store, target).unwrap();
        assert_eq!(
            sequential_header,
            upgrade_light_client_header(&original_header, target).unwrap()
        );
        assert_eq!(
            sequential_update,
            upgrade_light_client_update(&fixture.update, target).unwrap()
        );
        assert_eq!(
            sequential_bootstrap,
            upgrade_light_client_bootstrap(&original_bootstrap, target).unwrap()
        );
        let mut direct = Fixture::new(ForkName::Altair);
        upgrade_light_client_store(&mut direct.store, target).unwrap();
        assert_eq!(
            format!("{:?}", sequential_store),
            format!("{:?}", direct.store)
        );
        let before = format!("{:?}", sequential_store);
        upgrade_light_client_store(&mut sequential_store, target).unwrap();
        assert_eq!(format!("{:?}", sequential_store), before);
        assert_eq!(
            upgrade_light_client_header(&sequential_header, target).unwrap(),
            sequential_header
        );
        assert_eq!(
            upgrade_light_client_update(&sequential_update, target).unwrap(),
            sequential_update
        );
    }
}

#[test]
fn electra_adds_leading_zero_padding_without_changing_historical_merkle_siblings() {
    for source in [ForkName::Altair, ForkName::Capella, ForkName::Deneb] {
        let mut fixture = Fixture::new(source);
        let original = fixture.update.clone();
        let original_view = UpdateView::new(&original);
        fixture.update = upgrade_light_client_update(&original, ForkName::Electra).unwrap();
        fixture.data_fork = ForkName::Electra;
        upgrade_light_client_store(&mut fixture.store, ForkName::Electra).unwrap();
        let view = UpdateView::new(&fixture.update);
        assert_eq!(view.finality_branch[0], Hash256::default());
        assert_eq!(&view.finality_branch[1..], original_view.finality_branch);
        assert_eq!(view.next_committee_branch[0], Hash256::default());
        assert_eq!(
            &view.next_committee_branch[1..],
            original_view.next_committee_branch
        );
        fixture.valid();
        let upgraded = fixture.update.clone();
        with_update!(
            &mut fixture.update,
            inner,
            inner.finality_branch[0] = hash(160)
        );
        fixture.invalid(LightClientSyncError::InvalidFinalityProof);
        fixture.update = upgraded;
        with_update!(
            &mut fixture.update,
            inner,
            inner.next_sync_committee_branch[0] = hash(161)
        );
        fixture.invalid(LightClientSyncError::InvalidNextSyncCommitteeProof);

        let bootstrap = bootstrap_for(source, &fixture.spec, &fixture.current_keys);
        let upgraded = upgrade_light_client_bootstrap(&bootstrap, ForkName::Electra).unwrap();
        let LightClientBootstrap::Electra(mut inner) = upgraded else {
            unreachable!()
        };
        let original_branch: &[Hash256] = match &bootstrap {
            LightClientBootstrap::Altair(inner) => inner.current_sync_committee_branch.as_ref(),
            LightClientBootstrap::Capella(inner) => inner.current_sync_committee_branch.as_ref(),
            LightClientBootstrap::Deneb(inner) => inner.current_sync_committee_branch.as_ref(),
            _ => unreachable!(),
        };
        assert_eq!(inner.current_sync_committee_branch[0], Hash256::default());
        assert_eq!(&inner.current_sync_committee_branch[1..], original_branch);
        inner.current_sync_committee_branch[0] = hash(162);
        let result = initialize_light_client_store(
            fixture
                .store
                .verified_checkpoint_header()
                .beacon_block_root(),
            &LightClientBootstrap::Electra(inner),
            ForkName::Electra,
            LightClientStoreSchema::Electra,
            &fixture.spec,
        );
        assert!(matches!(
            result,
            Err(LightClientSyncError::InvalidCurrentSyncCommitteeProof)
        ));
    }
}

#[test]
fn absent_and_genesis_finality_remain_default_through_all_upgrades() {
    for finality in [false, true] {
        for target in FORKS {
            let mut fixture = Fixture::new(ForkName::Altair);
            fixture.omit_finality();
            fixture.omit_next_committee();
            fixture.refresh_proofs(finality, false);
            fixture.sign_all(false);
            fixture.update = upgrade_light_client_update(&fixture.update, target).unwrap();
            fixture.data_fork = target;
            upgrade_light_client_store(&mut fixture.store, target).unwrap();
            let view = UpdateView::new(&fixture.update);
            assert_eq!(
                view.finalized_header,
                upgrade_light_client_header(
                    &LightClientHeader::Altair(LightClientHeaderAltair::<E>::default()),
                    target
                )
                .unwrap()
            );
            assert!(
                view.next_committee_branch
                    .iter()
                    .all(|node| *node == Hash256::default())
            );
            if !finality {
                assert!(
                    view.finality_branch
                        .iter()
                        .all(|node| *node == Hash256::default())
                );
            }
            fixture.valid();
            fixture.process().unwrap();
            assert_eq!(finalized_slot(&fixture.store), 1);
            assert_eq!(optimistic_slot(&fixture.store), 3);
            assert_eq!(
                fixture.store.verified_checkpoint_header().slot(),
                Slot::new(1)
            );
        }
    }
}

#[test]
fn populated_store_upgrade_preserves_cache_counters_committees_and_all_beacon_roots() {
    let mut fixture = Fixture::new(ForkName::Altair);
    fixture.process().unwrap();
    fixture.set_slots(64, 65, 66);
    with_update!(&mut fixture.update, inner, {
        inner.next_sync_committee = committee(&fixture.current_keys);
    });
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(22, true);
    fixture.set_slots(65, 66, 67);
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(17, true);
    let finalized = fixture.store.spec_finalized_header().clone();
    let optimistic = fixture.store.optimistic_header().clone();
    let checkpoint = fixture.store.verified_checkpoint_header().clone();
    let best = fixture.store.best_valid_update().unwrap().clone();
    let current = fixture.store.current_sync_committee().clone();
    let next = fixture.store.next_sync_committee().cloned();
    let previous_count = fixture.store.previous_max_active_participants();
    let current_count = fixture.store.current_max_active_participants();
    assert_eq!((previous_count, current_count), (32, 17));
    for target in FORKS {
        upgrade_light_client_store(&mut fixture.store, target).unwrap();
        assert_eq!(
            fixture.store.store_schema(),
            LightClientStoreSchema::try_from(target).unwrap()
        );
        assert_eq!(
            fixture.store.spec_finalized_header(),
            &upgrade_light_client_header(&finalized, target).unwrap()
        );
        assert_eq!(
            fixture.store.optimistic_header(),
            &upgrade_light_client_header(&optimistic, target).unwrap()
        );
        assert_checkpoint_preserved(&fixture.store, &checkpoint, target);
        assert_eq!(
            fixture.store.best_valid_update(),
            Some(&upgrade_light_client_update(&best, target).unwrap())
        );
        assert_eq!(fixture.store.current_sync_committee(), &current);
        assert_eq!(fixture.store.next_sync_committee(), next.as_ref());
        assert_eq!(
            fixture.store.previous_max_active_participants(),
            previous_count
        );
        assert_eq!(
            fixture.store.current_max_active_participants(),
            current_count
        );
    }
    // Force consumes the upgraded cached update rather than retaining an old-format hidden copy.
    fixture.force(129).unwrap();
    assert_eq!(
        fixture.store.spec_finalized_header(),
        &upgrade_light_client_header(&UpdateView::new(&best).finalized_header, ForkName::Fulu)
            .unwrap()
    );
    assert_checkpoint_preserved(&fixture.store, &checkpoint, ForkName::Fulu);
    assert!(fixture.store.best_valid_update().is_none());
}

#[test]
fn same_schema_upgrade_normalizes_original_headers_from_newer_ceiling_initialization() {
    let fixture = Fixture::new(ForkName::Altair);
    let bootstrap = bootstrap_for(ForkName::Altair, &fixture.spec, &fixture.current_keys);
    let checkpoint = fixture.store.verified_checkpoint_header();
    let mut store = initialize_light_client_store(
        checkpoint.beacon_block_root(),
        &bootstrap,
        ForkName::Altair,
        LightClientStoreSchema::Electra,
        &fixture.spec,
    )
    .unwrap();
    assert!(matches!(
        store.spec_finalized_header(),
        LightClientHeader::Altair(_)
    ));
    upgrade_light_client_store(&mut store, ForkName::Electra).unwrap();
    assert!(matches!(
        store.spec_finalized_header(),
        LightClientHeader::Electra(_)
    ));
    assert!(matches!(
        store.optimistic_header(),
        LightClientHeader::Electra(_)
    ));
    assert_checkpoint_preserved(&store, checkpoint, ForkName::Electra);
    let before = format!("{store:?}");
    upgrade_light_client_store(&mut store, ForkName::Electra).unwrap();
    assert_eq!(format!("{store:?}"), before);
}

#[test]
fn downgrade_and_unsupported_forks_are_rejected_without_mutation() {
    for source in FORKS {
        let mut fixture = Fixture::new(source);
        fixture.process_with_participants(1, false);
        let header = fixture.store.spec_finalized_header().clone();
        let bootstrap = bootstrap_for(source, &fixture.spec, &fixture.current_keys);
        let before = format!("{:?}", fixture.store);
        for target in [ForkName::Base, ForkName::Gloas, ForkName::Heze] {
            let error = || LightClientSyncError::UnsupportedFork(target);
            assert_eq!(upgrade_light_client_header(&header, target), Err(error()));
            assert_eq!(
                upgrade_light_client_update(&fixture.update, target),
                Err(error())
            );
            assert_eq!(
                upgrade_light_client_bootstrap(&bootstrap, target),
                Err(error())
            );
            assert_eq!(
                upgrade_light_client_store(&mut fixture.store, target),
                Err(error())
            );
            assert_eq!(format!("{:?}", fixture.store), before);
        }
        for target in FORKS.into_iter().filter(|fork| *fork < source) {
            if source == ForkName::Bellatrix && target == ForkName::Altair {
                continue;
            }
            let error = || LightClientSyncError::DataForkDowngrade {
                current: source,
                requested: target,
            };
            assert_eq!(upgrade_light_client_header(&header, target), Err(error()));
            assert_eq!(
                upgrade_light_client_update(&fixture.update, target),
                Err(error())
            );
            assert_eq!(
                upgrade_light_client_bootstrap(&bootstrap, target),
                Err(error())
            );
            let current = LightClientStoreSchema::try_from(source).unwrap();
            let requested = LightClientStoreSchema::try_from(target).unwrap();
            if requested < current {
                assert_eq!(
                    upgrade_light_client_store(&mut fixture.store, target),
                    Err(LightClientSyncError::StoreSchemaDowngrade { current, requested })
                );
                assert_eq!(format!("{:?}", fixture.store), before);
            } else {
                // Fulu and Electra share a store schema, but the Rust data format cannot regress.
                assert_eq!(
                    upgrade_light_client_store(&mut fixture.store, target),
                    Err(error())
                );
                assert_eq!(format!("{:?}", fixture.store), before);
            }
        }
    }
}

#[test]
fn cached_update_upgrade_failure_does_not_partially_upgrade_older_store_headers() {
    let mut fixture = Fixture::new(ForkName::Altair);
    let bootstrap = bootstrap_for(ForkName::Altair, &fixture.spec, &fixture.current_keys);
    fixture.store = initialize_light_client_store(
        fixture
            .store
            .verified_checkpoint_header()
            .beacon_block_root(),
        &bootstrap,
        ForkName::Altair,
        LightClientStoreSchema::Electra,
        &fixture.spec,
    )
    .unwrap();
    fixture.process().unwrap();
    fixture.set_slots(2, 4, 5);
    fixture.refresh_proofs(true, true);
    fixture.sign_indices(&[0], false);
    fixture.update = upgrade_light_client_update(&fixture.update, ForkName::Fulu).unwrap();
    fixture.data_fork = ForkName::Fulu;
    fixture.process().unwrap();

    // Electra's schema accepts Fulu data. A weak update only changes the cache, leaving
    // the old headers in place. Their conversions succeed before the cached update fails.
    assert!(matches!(
        fixture.store.spec_finalized_header(),
        LightClientHeader::Altair(_)
    ));
    assert!(matches!(
        fixture.store.optimistic_header(),
        LightClientHeader::Altair(_)
    ));
    assert!(matches!(
        fixture.store.best_valid_update(),
        Some(LightClientUpdate::Fulu(_))
    ));
    let checkpoint = fixture.store.verified_checkpoint_header().clone();
    let before = format!("{:?}", fixture.store);
    assert_eq!(
        upgrade_light_client_store(&mut fixture.store, ForkName::Electra),
        Err(LightClientSyncError::DataForkDowngrade {
            current: ForkName::Fulu,
            requested: ForkName::Electra,
        })
    );
    assert_eq!(format!("{:?}", fixture.store), before);

    upgrade_light_client_store(&mut fixture.store, ForkName::Fulu).unwrap();
    assert_checkpoint_preserved(&fixture.store, &checkpoint, ForkName::Fulu);
    assert_eq!(fixture.store.best_valid_update(), Some(&fixture.update));
}

#[test]
fn new_fork_updates_require_store_upgrade_but_preserve_the_historical_checkpoint_fork() {
    for (source, target) in [
        (ForkName::Bellatrix, ForkName::Capella),
        (ForkName::Capella, ForkName::Deneb),
        (ForkName::Deneb, ForkName::Electra),
    ] {
        let mut spec = source.make_genesis_spec(E::default_spec());
        match target {
            ForkName::Capella => {
                spec.bellatrix_fork_epoch = Some(Epoch::new(0));
                spec.capella_fork_epoch = Some(Epoch::new(2));
            }
            ForkName::Deneb => spec.deneb_fork_epoch = Some(Epoch::new(2)),
            ForkName::Electra => spec.electra_fork_epoch = Some(Epoch::new(2)),
            _ => unreachable!(),
        }
        let mut old = Fixture::at_slots(source, spec.clone(), 1, 2, 3, 4);
        old.process().unwrap();
        let checkpoint = old.store.verified_checkpoint_header().clone();
        let mut new = Fixture::at_slots(target, spec, 1, 16, 17, 18);
        new.store = old.store;
        new.assert_process_error(LightClientSyncError::UpdateSchemaTooNew {
            update_schema: LightClientStoreSchema::try_from(target).unwrap(),
            store_schema: LightClientStoreSchema::try_from(source).unwrap(),
        });
        upgrade_light_client_store(&mut new.store, target).unwrap();
        assert_checkpoint_preserved(&new.store, &checkpoint, target);
        new.process().unwrap();
        assert_eq!(finalized_slot(&new.store), 16);
        assert_eq!(new.store.verified_checkpoint_header().fork(), target);
        assert_eq!(new.store.verified_checkpoint_header().slot(), Slot::new(16));
    }
}

#[test]
fn force_learned_committees_do_not_regain_checkpoint_trust_after_upgrade() {
    let mut fixture = Fixture::new(ForkName::Altair);
    let checkpoint = fixture.store.verified_checkpoint_header().clone();
    fixture.process_with_participants(1, false);
    fixture.force(66).unwrap();
    upgrade_light_client_store(&mut fixture.store, ForkName::Fulu).unwrap();
    fixture.update = upgrade_light_client_update(&fixture.update, ForkName::Fulu).unwrap();
    fixture.data_fork = ForkName::Fulu;
    assert_checkpoint_preserved(&fixture.store, &checkpoint, ForkName::Fulu);
    fixture.set_slots(3, 63, 64);
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(32, true);
    assert_checkpoint_preserved(&fixture.store, &checkpoint, ForkName::Fulu);
    fixture.set_slots(64, 65, 66);
    with_update!(
        &mut fixture.update,
        inner,
        inner.next_sync_committee = committee(&fixture.current_keys)
    );
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(32, true);
    assert_eq!(finalized_slot(&fixture.store), 64);
    assert_checkpoint_preserved(&fixture.store, &checkpoint, ForkName::Fulu);
    fixture.set_slots(128, 129, 130);
    with_update!(
        &mut fixture.update,
        inner,
        inner.next_sync_committee = committee(&fixture.next_keys)
    );
    fixture.refresh_proofs(true, true);
    fixture.process_with_participants(32, false);
    assert_eq!(finalized_slot(&fixture.store), 128);
    assert_checkpoint_preserved(&fixture.store, &checkpoint, ForkName::Fulu);
}

#[test]
fn authenticated_current_and_next_committees_remain_trusted_after_upgrade() {
    for trusted_next in [false, true] {
        let mut fixture = Fixture::new(ForkName::Altair);
        fixture.process_with_participants(if trusted_next { 32 } else { 1 }, false);
        if !trusted_next {
            fixture.force(66).unwrap();
        }
        upgrade_light_client_store(&mut fixture.store, ForkName::Fulu).unwrap();
        fixture.update = upgrade_light_client_update(&fixture.update, ForkName::Fulu).unwrap();
        fixture.data_fork = ForkName::Fulu;
        if !trusted_next {
            // Original authenticated current committee can independently confirm forced finality.
            fixture.process_with_participants(32, false);
            assert_eq!(
                fixture.store.verified_checkpoint_header().slot(),
                Slot::new(2)
            );
        }
        fixture.set_slots(64, 65, 66);
        with_update!(
            &mut fixture.update,
            inner,
            inner.next_sync_committee = committee(&fixture.current_keys)
        );
        fixture.refresh_proofs(true, true);
        fixture.process_with_participants(32, true);
        assert_eq!(
            fixture.store.verified_checkpoint_header().slot(),
            Slot::new(64)
        );
        assert_eq!(
            fixture.store.verified_checkpoint_header().fork(),
            ForkName::Altair
        );
    }
}

#[test]
fn representation_upgrade_does_not_certify_invalid_signatures_or_execution_proofs() {
    let mut fixture = Fixture::new(ForkName::Capella);
    with_update!(
        &mut fixture.update,
        inner,
        inner.sync_aggregate.sync_committee_signature = AggregateSignature::infinity()
    );
    fixture.update = upgrade_light_client_update(&fixture.update, ForkName::Fulu).unwrap();
    fixture.data_fork = ForkName::Fulu;
    upgrade_light_client_store(&mut fixture.store, ForkName::Fulu).unwrap();
    fixture.invalid(LightClientSyncError::InvalidSyncCommitteeSignature);
    fixture.sign_all(false);
    let LightClientUpdate::Fulu(inner) = &mut fixture.update else {
        unreachable!()
    };
    inner.attested_header.execution_branch[0] = hash(163);
    fixture.invalid(LightClientSyncError::InvalidExecutionPayloadProof);
}

#[test]
fn deneb_execution_fields_and_proof_survive_electra_and_fulu_representation_changes() {
    let spec = ForkName::Deneb.make_genesis_spec(E::default_spec());
    let mut original = header(ForkName::Deneb, &spec, Slot::new(3), hash(170));
    let LightClientHeader::Deneb(inner) = &mut original else {
        unreachable!()
    };
    inner.execution.parent_hash = ExecutionBlockHash(hash(171));
    inner.execution.state_root = hash(172);
    inner.execution.receipts_root = hash(173);
    inner.execution.prev_randao = hash(174);
    inner.execution.block_number = 175;
    inner.execution.gas_limit = 176;
    inner.execution.gas_used = 177;
    inner.execution.timestamp = 178;
    inner.execution.extra_data = vec![179, 180].try_into().unwrap();
    inner.execution.base_fee_per_gas = types::Uint256::from(181u64);
    inner.execution.transactions_root = hash(182);
    inner.execution.withdrawals_root = hash(183);
    inner.execution.blob_gas_used = 184;
    inner.execution.excess_blob_gas = 185;
    inner.execution.logs_bloom[0] = 186;
    let execution_root = inner.execution.tree_hash_root();
    let tree = state_tree(4, &[(9, execution_root)]);
    inner.beacon.body_root = tree.hash();
    inner.execution_branch = tree.generate_proof(9, 4).unwrap().1.try_into().unwrap();
    let original_branch = inner.execution_branch.clone();
    for target in [ForkName::Electra, ForkName::Fulu] {
        let upgraded = upgrade_light_client_header(&original, target).unwrap();
        validate_light_client_header(&upgraded, target, &spec).unwrap();
        assert_eq!(beacon_header(&upgraded), beacon_header(&original));
        // These forks share Deneb's execution SSZ layout, so equality of its root checks every field.
        match upgraded {
            LightClientHeader::Electra(inner) => {
                assert_eq!(inner.execution.tree_hash_root(), execution_root);
                assert_eq!(inner.execution_branch, original_branch);
            }
            LightClientHeader::Fulu(inner) => {
                assert_eq!(inner.execution.tree_hash_root(), execution_root);
                assert_eq!(inner.execution_branch, original_branch);
            }
            _ => unreachable!(),
        }
    }
}
