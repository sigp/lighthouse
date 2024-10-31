use bls::PublicKeyBytes;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::Rng;
use ssz::Decode;
use store::{
    hdiff::{HDiff, HDiffBuffer},
    StoreConfig,
};
use types::{BeaconState, Epoch, Eth1Data, EthSpec, ForkName, MainnetEthSpec as E, Validator};

pub fn all_benches(c: &mut Criterion) {
    let fork = ForkName::Base;
    let spec = fork.make_genesis_spec(E::default_spec());
    let genesis_time = 0;
    let eth1_data = Eth1Data::default();
    let config = StoreConfig::default();
    let mut rng = rand::thread_rng();
    let validator_mutations = 1000;
    let validator_additions = 100;

    for n in [1_000_000, 1_500_000, 2_000_000] {
        let mut source_state = BeaconState::<E>::new(genesis_time, eth1_data.clone(), &spec);

        for _ in 0..n {
            append_validator(&mut source_state, &mut rng);
        }

        let mut target_state = source_state.clone();
        // Change all balances
        for i in 0..n {
            let balance = target_state.balances_mut().get_mut(i).unwrap();
            *balance += rng.gen_range(1..=1_000_000);
        }
        // And some validator records
        for _ in 0..validator_mutations {
            let index = rng.gen_range(1..n);
            // TODO: Only change a few things, and not the pubkey
            *target_state.validators_mut().get_mut(index).unwrap() = rand_validator(&mut rng);
        }
        for _ in 0..validator_additions {
            append_validator(&mut target_state, &mut rng);
        }

        let source = HDiffBuffer::from_state(source_state);
        let target = HDiffBuffer::from_state(target_state);
        let diff = HDiff::compute(&source, &target, &config).unwrap();

        c.bench_function(
            &format!("apply hdiff n={n} v_mut={validator_mutations} v_add={validator_additions}"),
            |b| {
                let mut source = source.clone();
                b.iter(|| {
                    diff.apply(&mut source, &config).unwrap();
                    println!("diff size {}", diff.size());
                })
            },
        );
    }
}

fn rand_validator(mut rng: impl Rng) -> Validator {
    let mut pubkey = [0u8; 48];
    rng.fill_bytes(&mut pubkey);
    let withdrawal_credentials: [u8; 32] = rng.gen();

    Validator {
        pubkey: PublicKeyBytes::from_ssz_bytes(&pubkey).unwrap(),
        withdrawal_credentials: withdrawal_credentials.into(),
        slashed: false,
        effective_balance: 32_000_000_000,
        activation_eligibility_epoch: Epoch::max_value(),
        activation_epoch: Epoch::max_value(),
        exit_epoch: Epoch::max_value(),
        withdrawable_epoch: Epoch::max_value(),
    }
}

fn append_validator(state: &mut BeaconState<E>, mut rng: impl Rng) {
    state
        .balances_mut()
        .push(32_000_000_000 + rng.gen_range(1..=1_000_000_000))
        .unwrap();
    if let Ok(inactivity_scores) = state.inactivity_scores_mut() {
        inactivity_scores.push(0).unwrap();
    }
    state
        .validators_mut()
        .push(rand_validator(&mut rng))
        .unwrap();
}

criterion_group! {
  name = benches;
  config = Criterion::default().sample_size(10);
  targets = all_benches
}
criterion_main!(benches);
