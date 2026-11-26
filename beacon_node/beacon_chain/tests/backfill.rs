#![cfg(not(feature = "test_backfill"))]

use beacon_chain::test_utils::BeaconChainHarness;
use std::sync::Arc;
use types::{Epoch, EthSpec, ForkName, Spec};

type E = Spec;

#[tokio::test]
async fn genesis_backfill_slot_uses_gloas_range_after_fork() {
    let mut spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
    let pre_gloas_range = spec
        .compute_min_epochs_for_block_requests(Epoch::new(0))
        .unwrap();
    let gloas_fork_epoch = Epoch::new(pre_gloas_range + 10);
    spec.gloas_fork_epoch = Some(gloas_fork_epoch);
    let gloas_range = spec
        .compute_min_epochs_for_block_requests(gloas_fork_epoch)
        .unwrap();
    assert!(gloas_range < pre_gloas_range);

    let harness = BeaconChainHarness::builder(E::default())
        .spec(Arc::new(spec))
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let last_pre_gloas_epoch = gloas_fork_epoch - 1;
    harness.set_current_slot(last_pre_gloas_epoch.start_slot(E::slots_per_epoch()));
    assert_eq!(
        harness.chain.genesis_backfill_slot(),
        (last_pre_gloas_epoch - pre_gloas_range).start_slot(E::slots_per_epoch())
    );

    harness.set_current_slot(gloas_fork_epoch.start_slot(E::slots_per_epoch()));
    assert_eq!(
        harness.chain.genesis_backfill_slot(),
        (gloas_fork_epoch - gloas_range).start_slot(E::slots_per_epoch())
    );
}
