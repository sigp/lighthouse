//! These examples only really exist so we can use them for flamegraph. If they get annoying to
//! maintain, feel free to delete.

use rayon::prelude::*;
use ssz::{Decode, Encode};
use std::convert::TryInto;
use store::BeaconStateStorageContainer;
use types::{
    test_utils::generate_deterministic_keypair, BeaconState, Epoch, Eth1Data, EthSpec, Hash256,
    MainnetEthSpec, Validator,
};

type E = MainnetEthSpec;

fn get_state<E: EthSpec>(validator_count: usize) -> BeaconState<E> {
    let spec = &E::default_spec();
    let eth1_data = Eth1Data {
        deposit_root: Hash256::zero(),
        deposit_count: 0,
        block_hash: Hash256::zero(),
    };

    let mut state = BeaconState::new(0, eth1_data, spec);

    for i in 0..validator_count {
        state.balances.push(i as u64).expect("should add balance");
    }

    state.validators = (0..validator_count)
        .collect::<Vec<_>>()
        .par_iter()
        .map(|&i| Validator {
            pubkey: generate_deterministic_keypair(i).pk.into(),
            withdrawal_credentials: Hash256::from_low_u64_le(i as u64),
            effective_balance: spec.max_effective_balance,
            slashed: false,
            activation_eligibility_epoch: Epoch::new(0),
            activation_epoch: Epoch::new(0),
            exit_epoch: Epoch::from(u64::max_value()),
            withdrawable_epoch: Epoch::from(u64::max_value()),
        })
        .collect::<Vec<_>>()
        .into();

    state.build_all_caches(spec).expect("should build caches");

    state
}

fn main() {
    let validator_count = 1_024;
    let state = get_state::<E>(validator_count);
    let storage_container = BeaconStateStorageContainer::new(&state);

    for _ in 0..1024 {
        let container_bytes = storage_container.as_ssz_bytes();
        let _: BeaconState<E> = BeaconStateStorageContainer::from_ssz_bytes(&container_bytes)
            .expect("should decode")
            .try_into()
            .expect("should convert into state");
    }
}
