//! Exercise the bounded consumer against Lighthouse's real HTTP routes and light-client cache.
//!
//! This is a wire/consumer contract test using selected real producer events after non-genesis
//! finalization, before a fork and after post-fork finalization. It does not establish correct
//! genesis-update production or continuous availability while attested/finalized schemas differ.

use beacon_chain::test_utils::{
    AttestationStrategy, BlockStrategy, LightClientStrategy, SyncCommitteeStrategy,
};
use decentralized_checkpoint_sync_client::{
    HttpLightClientDataSource, LightClientDataSource, RequestLimits, SyncPolicy, UpdateRange,
    sync_verified_finalized_header,
};
use http_api::test_utils::InteractiveTester;
use std::{sync::Arc, time::Duration};
use types::{Epoch, EthSpec, ForkName, MinimalEthSpec, Slot};

type E = MinimalEthSpec;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn light_client_consumer_from_real_http_across_forks() {
    for (bootstrap_fork, update_fork) in [
        (ForkName::Altair, ForkName::Altair),
        (ForkName::Bellatrix, ForkName::Capella),
        (ForkName::Deneb, ForkName::Electra),
        (ForkName::Electra, ForkName::Fulu),
    ] {
        let mut spec = bootstrap_fork.make_genesis_spec(E::default_spec());
        let fork_epoch = Some(Epoch::new(7));
        match update_fork {
            ForkName::Altair => {}
            ForkName::Capella => spec.capella_fork_epoch = fork_epoch,
            ForkName::Electra => spec.electra_fork_epoch = fork_epoch,
            ForkName::Fulu => spec.fulu_fork_epoch = fork_epoch,
            _ => unreachable!("the cases only schedule supported light-client forks"),
        }

        let tester = InteractiveTester::<E>::new(Some(spec.clone()), 24).await;
        let harness = &tester.harness;
        let mut trusted_root = None;
        // Cache the bootstrap parent at slot 32, a pre-fork update, and a post-fork update.
        // Non-genesis finality is already established when the first event is delivered.
        // Deliver each event while its parent state is still available, as the live producer
        // does, rather than replaying it after old states have been pruned by finalization.
        for signature_slot in [
            4 * E::slots_per_epoch() + 1,
            6 * E::slots_per_epoch(),
            10 * E::slots_per_epoch() + 1,
        ] {
            let block_count = signature_slot - harness.get_current_slot().as_u64();
            harness.advance_slot();
            harness
                .extend_chain_with_sync(
                    block_count as usize,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                    SyncCommitteeStrategy::AllValidators,
                    LightClientStrategy::Disabled,
                )
                .await;
            let block = harness.chain.head_beacon_block();
            assert_eq!(block.slot(), Slot::new(signature_slot));
            if signature_slot == 6 * E::slots_per_epoch() {
                // Trust is supplied out-of-band from the chain, not from the HTTP provider.
                trusted_root = Some(harness.finalized_checkpoint().root);
            }
            // The imported block's aggregate signs its parent, not its own root. The harness's
            // op-pool-based LC helper does not represent this event. Every event must succeed.
            let sync_aggregate = block.message().body().sync_aggregate().unwrap().clone();
            harness
                .chain
                .recompute_and_cache_light_client_updates((
                    block.parent_root(),
                    block.slot(),
                    sync_aggregate,
                ))
                .unwrap_or_else(|error| {
                    panic!(
                        "{bootstrap_fork:?} -> {update_fork:?}, producer slot {signature_slot}: {error:?}"
                    )
                });
        }
        harness.advance_slot();
        let trusted_root = trusted_root.expect("recorded the pre-fork finalized checkpoint");
        let trusted_block = harness
            .chain
            .get_blinded_block(&trusted_root)
            .unwrap()
            .unwrap();
        assert_eq!(
            spec.fork_name_at_slot::<E>(trusted_block.slot()),
            bootstrap_fork
        );

        let mut source = HttpLightClientDataSource::new(tester.client.server().clone()).unwrap();
        let limits = RequestLimits::new(Duration::from_secs(10), 4 * 1024 * 1024).unwrap();
        let bootstrap =
            LightClientDataSource::<E>::get_bootstrap(&mut source, trusted_root, limits)
                .await
                .unwrap();
        let (expected_bootstrap, expected_fork) = harness
            .chain
            .get_light_client_bootstrap(&trusted_root)
            .unwrap()
            .unwrap();
        assert_eq!(bootstrap.data.data_fork, expected_fork);
        assert_eq!(bootstrap.data.data_fork, bootstrap_fork);
        assert_eq!(bootstrap.data.data, expected_bootstrap);
        assert!(bootstrap.bytes_received > 0);

        // Cross a committee period as well as a fork, so the driver must authenticate a successor.
        let range = UpdateRange::new(0, 2).unwrap();
        let updates = LightClientDataSource::<E>::get_updates(&mut source, range, limits)
            .await
            .unwrap();
        let expected_updates = harness.chain.get_light_client_updates(0, 2).unwrap();
        assert_eq!(expected_updates.len(), 2);
        assert_eq!(updates.data.len(), expected_updates.len());
        for (actual, expected) in updates.data.iter().zip(expected_updates) {
            assert_eq!(
                actual.data_fork,
                spec.fork_name_at_slot::<E>(*expected.signature_slot())
            );
            assert_eq!(actual.data, expected);
        }
        assert!(updates.bytes_received > 0);

        let finality = LightClientDataSource::<E>::get_finality_update(&mut source, limits)
            .await
            .unwrap();
        let expected_finality = harness
            .chain
            .light_client_server_cache
            .get_latest_finality_update()
            .expect("the real chain produced a finality update");
        assert_eq!(finality.data.data_fork, update_fork);
        assert_eq!(finality.data.data, expected_finality);
        assert!(finality.bytes_received > 0);
        let expected_root = expected_finality.get_finalized_header_root();
        let expected_block = harness
            .chain
            .get_blinded_block(&expected_root)
            .unwrap()
            .unwrap();
        assert!(expected_block.slot() > trusted_block.slot());
        assert_eq!(
            spec.fork_name_at_slot::<E>(expected_block.slot()),
            update_fork
        );

        let policy = SyncPolicy {
            max_finalized_lag_slots: harness.get_current_slot().as_u64()
                - expected_block.slot().as_u64(),
            max_updates_per_request: 2,
            request_limits: limits,
            sync_timeout: Duration::from_secs(30),
            max_requests: 3,
            max_updates: 3,
            max_total_response_bytes: 12 * 1024 * 1024,
            max_no_progress_requests: 1,
            max_retries: 0,
            initial_retry_delay: Duration::from_millis(1),
            max_retry_delay: Duration::from_millis(1),
        };
        let outcome = sync_verified_finalized_header::<E>(
            &mut source,
            trusted_root,
            Arc::new(spec),
            harness.get_current_state().genesis_validators_root(),
            &harness.chain.slot_clock,
            &policy,
        )
        .await
        .unwrap_or_else(|error| panic!("{bootstrap_fork:?} -> {update_fork:?}: {error:?}"));

        assert_eq!(outcome.header.beacon_block_root(), expected_root);
        assert_eq!(
            outcome.header.beacon_state_root(),
            *expected_block.message().state_root()
        );
        assert_eq!(outcome.header.slot(), expected_block.slot());
        assert_eq!(outcome.header.fork(), update_fork);
        assert!(outcome.usage.requests >= 2);
        assert!(outcome.usage.response_bytes > 0);
    }
}
