#[macro_use]
extern crate lazy_static;

use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main, Benchmark};
use store::{MemoryStore, Store};
use types::{BeaconBlock, BeaconState, EthSpec, MainnetEthSpec, MinimalEthSpec};

const INITIAL_HARNESS_BLOCKS: u64 = 8 * 2 - 1;
const VALIDATOR_COUNT: usize = 32_768;

type TestEthSpec = MinimalEthSpec;
type ThreadSafeReducedTree<T> = lmd_ghost::ThreadSafeReducedTree<MemoryStore, T>;
type BeaconChainHarness<T> =
    beacon_chain::test_utils::BeaconChainHarness<ThreadSafeReducedTree<T>, T>;

lazy_static! {
    static ref MINIMAL_HARNESS: BeaconChainHarness<MinimalEthSpec> = { get_harness() };
    static ref MAINNET_HARNESS: BeaconChainHarness<MainnetEthSpec> = { get_harness() };
}

fn get_harness<T: EthSpec>() -> BeaconChainHarness<T> {
    let harness = BeaconChainHarness::new(VALIDATOR_COUNT);

    harness.advance_slot();

    harness.extend_chain(
        INITIAL_HARNESS_BLOCKS as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    harness
}

fn bench_suite<T: EthSpec>(
    c: &mut Criterion,
    spec_desc: &str,
    harness: &'static BeaconChainHarness<T>,
) {
    let spec = TestEthSpec::default_spec();
    let block: BeaconBlock<T> = harness.chain.head().beacon_block.clone();
    let mut state = {
        let store = &harness.chain.store;
        let parent_block: BeaconBlock<T> = store
            .get(&block.parent_root)
            .expect("db should not error")
            .expect("parent block should exist");
        store
            .get::<BeaconState<T>>(&parent_block.state_root)
            .expect("db should not error")
            .expect("parent state should exist")
    };
    state_processing::per_slot_processing::<T>(&mut state, &spec)
        .expect("per slot processing should succeed");

    c.bench(
        &format!("{}/{}_validators", spec_desc, VALIDATOR_COUNT),
        Benchmark::new("per_block_processing/empty", move |b| {
            b.iter_batched_ref(
                || (spec.clone(), state.clone(), block.clone()),
                |(spec, ref mut state, block)| {
                    black_box(
                        state_processing::per_block_processing::<T>(state, &block, &spec)
                            .expect("block processing should succeed"),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );
}

fn all_benches(c: &mut Criterion) {
    bench_suite(c, "minimal", &MINIMAL_HARNESS);
    // bench_suite(c, "mainnet", &MAINNET_HARNESS);
}

criterion_group!(benches, all_benches,);
criterion_main!(benches);
