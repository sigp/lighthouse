#![cfg(test)]
use crate::per_epoch_processing::process_epoch;
use beacon_chain::test_utils::BeaconChainHarness;
use beacon_chain::types::{EthSpec, MinimalEthSpec};
use bls::Hash256;
use env_logger::{Builder, Env};
use types::Slot;

#[test]
fn runs_without_error() {
    Builder::from_env(Env::default().default_filter_or("error")).init();

    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .build();
    harness.advance_slot();

    let spec = MinimalEthSpec::default_spec();
    let target_slot =
        (MinimalEthSpec::genesis_epoch() + 4).end_slot(MinimalEthSpec::slots_per_epoch());

    let state = harness.get_current_state();
    harness.add_attested_blocks_at_slots(
        state,
        Hash256::zero(),
        (1..target_slot.as_u64())
            .map(Slot::new)
            .collect::<Vec<_>>()
            .as_slice(),
        (0..8).collect::<Vec<_>>().as_slice(),
    );
    let mut new_head_state = harness.get_current_state();

    process_epoch(&mut new_head_state, &spec).unwrap();
}

#[cfg(not(debug_assertions))]
mod release_tests {
    use super::*;
    use crate::{
        per_slot_processing::per_slot_processing, EpochProcessingError, SlotProcessingError,
    };
    use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
    use types::{Epoch, ForkName, InconsistentFork, MainnetEthSpec};

    #[test]
    fn altair_state_on_base_fork() {
        let mut spec = MainnetEthSpec::default_spec();
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        // The Altair fork happens at epoch 1.
        spec.altair_fork_epoch = Some(Epoch::new(1));

        let altair_state = {
            let harness = BeaconChainHarness::builder(MainnetEthSpec)
                .spec(spec.clone())
                .deterministic_keypairs(8)
                .fresh_ephemeral_store()
                .build();

            harness.advance_slot();

            harness.extend_chain(
                // Build out enough blocks so we get an Altair block at the very end of an epoch.
                (slots_per_epoch * 2 - 1) as usize,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            );

            harness.get_current_state()
        };

        // Pre-conditions for a valid test.
        assert_eq!(altair_state.fork_name(&spec).unwrap(), ForkName::Altair);
        assert_eq!(
            altair_state.slot(),
            altair_state.current_epoch().end_slot(slots_per_epoch)
        );

        // Check the state is valid before starting this test.
        process_epoch(&mut altair_state.clone(), &spec)
            .expect("state passes intial epoch processing");
        per_slot_processing(&mut altair_state.clone(), None, &spec)
            .expect("state passes intial slot processing");

        // Modify the spec so altair never happens.
        spec.altair_fork_epoch = None;

        let expected_err = InconsistentFork {
            fork_at_slot: ForkName::Base,
            object_fork: ForkName::Altair,
        };

        assert_eq!(altair_state.fork_name(&spec), Err(expected_err));
        assert_eq!(
            process_epoch(&mut altair_state.clone(), &spec),
            Err(EpochProcessingError::InconsistentStateFork(expected_err))
        );
        assert_eq!(
            per_slot_processing(&mut altair_state.clone(), None, &spec),
            Err(SlotProcessingError::InconsistentStateFork(expected_err))
        );
    }

    #[test]
    fn base_state_on_altair_fork() {
        let mut spec = MainnetEthSpec::default_spec();
        let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
        // The Altair fork never happens.
        spec.altair_fork_epoch = None;

        let base_state = {
            let harness = BeaconChainHarness::builder(MainnetEthSpec)
                .spec(spec.clone())
                .deterministic_keypairs(8)
                .fresh_ephemeral_store()
                .build();

            harness.advance_slot();

            harness.extend_chain(
                // Build out enough blocks so we get a block at the very end of an epoch.
                (slots_per_epoch * 2 - 1) as usize,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            );

            harness.get_current_state()
        };

        // Pre-conditions for a valid test.
        assert_eq!(base_state.fork_name(&spec).unwrap(), ForkName::Base);
        assert_eq!(
            base_state.slot(),
            base_state.current_epoch().end_slot(slots_per_epoch)
        );

        // Check the state is valid before starting this test.
        process_epoch(&mut base_state.clone(), &spec)
            .expect("state passes intial epoch processing");
        per_slot_processing(&mut base_state.clone(), None, &spec)
            .expect("state passes intial slot processing");

        // Modify the spec so Altair happens at the first epoch.
        spec.altair_fork_epoch = Some(Epoch::new(1));

        let expected_err = InconsistentFork {
            fork_at_slot: ForkName::Altair,
            object_fork: ForkName::Base,
        };

        assert_eq!(base_state.fork_name(&spec), Err(expected_err));
        assert_eq!(
            process_epoch(&mut base_state.clone(), &spec),
            Err(EpochProcessingError::InconsistentStateFork(expected_err))
        );
        assert_eq!(
            per_slot_processing(&mut base_state.clone(), None, &spec),
            Err(SlotProcessingError::InconsistentStateFork(expected_err))
        );
    }
}
