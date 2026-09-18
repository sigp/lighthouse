//! Benchmarks for the `/eth/v1/beacon/states/{state_id}/validator_balances` handler, calling it
//! in-process on a chain built with the test harness (no HTTP, no JSON).
//!
//! Run with: `cargo bench -p http_api --features bench`
use beacon_chain::test_utils::BeaconChainHarness;
use criterion::measurement::Measurement;
use criterion::{BenchmarkId, Criterion, criterion_main};
use eth2::types::{StateId as CoreStateId, ValidatorId};
use http_api::{StateId, get_beacon_state_validator_balances};
use perf_benchmarking::{HardwareCounter, Metric};
use types::MainnetEthSpec;

/// Number of validators in the benchmark chain's genesis state.
const VALIDATOR_COUNT: usize = 1_00_000;

fn bench_validator_balances<M: Measurement + 'static>(c: &mut Criterion<M>, prefix: &str) {
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .build();
    let chain = harness.chain.clone();

    let mut group = c.benchmark_group(format!("{prefix}/validator_balances"));
    group.sample_size(10);

    for no_validators in [10, 100, 1_000, 10_000] {
        let ids: Vec<ValidatorId> = (0..no_validators as u64).map(ValidatorId::Index).collect();
        group.bench_with_input(
            BenchmarkId::from_parameter(no_validators),
            &ids,
            |b, ids| {
                b.iter(|| {
                    get_beacon_state_validator_balances(
                        StateId(CoreStateId::Head),
                        chain.clone(),
                        Some(ids),
                    )
                    .unwrap()
                })
            },
        );
    }

    // ids is None, meaning no ids is provided, meaning to return balances of all validators
    group.bench_function("all", |b| {
        b.iter(|| {
            get_beacon_state_validator_balances(StateId(CoreStateId::Head), chain.clone(), None)
                .unwrap()
        })
    });
    group.finish();
}

fn time_benches() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_validator_balances(&mut criterion, "time");
}

fn cpu_instructions_benches() {
    match HardwareCounter::new(Metric::CpuInstructions) {
        Ok(measurement) => {
            let mut criterion = Criterion::default()
                .with_measurement(measurement)
                .configure_from_args();
            bench_validator_balances(&mut criterion, "CPU instructions");
        }
        Err(e) => eprintln!("Skipping CPU instructions benchmarks: {e}"),
    }
}

criterion_main!(time_benches, cpu_instructions_benches);
