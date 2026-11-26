#![cfg(test)]
use std::sync::Arc;

use beacon_chain::test_utils::BeaconChainHarness;
use types::*;

type E = MinimalEthSpec;

fn state_for_fork(fork: ForkName) -> (BeaconState<E>, ChainSpec) {
    let spec = Arc::new(fork.make_genesis_spec(E::default_spec()));
    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone())
        .deterministic_keypairs(8)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    (harness.get_current_state(), (*spec).clone())
}

fn assert_incorrect_variant(result: Result<u64, BeaconStateError>) {
    assert!(matches!(
        result,
        Err(BeaconStateError::IncorrectStateVariant)
    ));
}

#[test]
fn churn_limit_helpers_are_fork_gated() {
    let (deneb_state, deneb_spec) = state_for_fork(ForkName::Deneb);
    let (electra_state, electra_spec) = state_for_fork(ForkName::Electra);
    let (fulu_state, fulu_spec) = state_for_fork(ForkName::Fulu);
    let (gloas_state, gloas_spec) = state_for_fork(ForkName::Gloas);

    assert!(deneb_state.get_validator_churn_limit(&deneb_spec).is_ok());
    assert!(
        deneb_state
            .get_validator_activation_churn_limit(&deneb_spec)
            .is_ok()
    );
    for (state, spec) in [
        (&electra_state, &electra_spec),
        (&fulu_state, &fulu_spec),
        (&gloas_state, &gloas_spec),
    ] {
        assert_incorrect_variant(state.get_validator_churn_limit(spec));
        assert_incorrect_variant(state.get_validator_activation_churn_limit(spec));
    }

    for (state, spec) in [
        (&electra_state, &electra_spec),
        (&fulu_state, &fulu_spec),
        (&gloas_state, &gloas_spec),
    ] {
        assert!(state.get_balance_churn_limit(spec).is_ok());
        assert!(state.get_consolidation_churn_limit(spec).is_ok());
    }
    assert_incorrect_variant(deneb_state.get_balance_churn_limit(&deneb_spec));
    assert_incorrect_variant(deneb_state.get_consolidation_churn_limit(&deneb_spec));

    assert!(
        electra_state
            .get_activation_exit_churn_limit(&electra_spec)
            .is_ok()
    );
    assert!(
        fulu_state
            .get_activation_exit_churn_limit(&fulu_spec)
            .is_ok()
    );
    assert_incorrect_variant(deneb_state.get_activation_exit_churn_limit(&deneb_spec));
    assert_incorrect_variant(gloas_state.get_activation_exit_churn_limit(&gloas_spec));

    assert!(gloas_state.get_activation_churn_limit(&gloas_spec).is_ok());
    assert!(gloas_state.get_exit_churn_limit(&gloas_spec).is_ok());
    for (state, spec) in [
        (&deneb_state, &deneb_spec),
        (&electra_state, &electra_spec),
        (&fulu_state, &fulu_spec),
    ] {
        assert_incorrect_variant(state.get_activation_churn_limit(spec));
        assert_incorrect_variant(state.get_exit_churn_limit(spec));
    }
}
