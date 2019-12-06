//! These examples only really exist so we can use them for flamegraph. If they get annoying to
//! maintain, feel free to delete.

use ssz::{Decode, Encode};
use types::{
    test_utils::generate_deterministic_keypair, BeaconState, Eth1Data, EthSpec, Hash256,
    MinimalEthSpec, Validator,
};

type E = MinimalEthSpec;

fn get_state(validator_count: usize) -> BeaconState<E> {
    let spec = &E::default_spec();
    let eth1_data = Eth1Data {
        deposit_root: Hash256::zero(),
        deposit_count: 0,
        block_hash: Hash256::zero(),
    };

    let mut state = BeaconState::new(0, eth1_data, spec);

    for i in 0..validator_count {
        state.balances.push(i as u64).expect("should add balance");
        state
            .validators
            .push(Validator {
                pubkey: generate_deterministic_keypair(i).pk.into(),
                withdrawal_credentials: Hash256::from_low_u64_le(i as u64),
                effective_balance: i as u64,
                slashed: i % 2 == 0,
                activation_eligibility_epoch: i.into(),
                activation_epoch: i.into(),
                exit_epoch: i.into(),
                withdrawable_epoch: i.into(),
            })
            .expect("should add validator");
    }

    state
}

fn main() {
    let validator_count = 1_024;
    let state = get_state(validator_count);

    for _ in 0..1_024 {
        let state_bytes = state.as_ssz_bytes();
        let _: BeaconState<E> = BeaconState::from_ssz_bytes(&state_bytes).expect("should decode");
    }
}
