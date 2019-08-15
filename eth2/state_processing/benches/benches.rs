#[macro_use]
extern crate lazy_static;
extern crate env_logger;

mod benching_block_builder;

use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use benching_block_builder::BenchingBlockBuidler;
use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main, Benchmark};
use store::{MemoryStore, Store};
use types::test_utils::TestingBeaconStateBuilder;
use types::{BeaconBlock, BeaconState, EthSpec, MainnetEthSpec, MinimalEthSpec, Slot};

const INITIAL_HARNESS_BLOCKS: u64 = 8 * 2 - 1;
const VALIDATOR_COUNT: usize = 3_768;

type TestEthSpec = MinimalEthSpec;
type ThreadSafeReducedTree<T> = lmd_ghost::ThreadSafeReducedTree<MemoryStore, T>;
type BeaconChainHarness<T> =
    beacon_chain::test_utils::BeaconChainHarness<ThreadSafeReducedTree<T>, T>;

lazy_static! {}

fn bench_suite<T: EthSpec>(c: &mut Criterion, spec_desc: &str) {
    let spec = TestEthSpec::default_spec();
    let mut builder: BenchingBlockBuidler<T> = BenchingBlockBuidler::new(VALIDATOR_COUNT, &spec);
    builder.set_slot(Slot::from(T::slots_per_epoch() * 3 - 2), &spec);
    builder.build_caches(&spec);
    let (block, state) = builder.build(&spec);

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
    env_logger::init();

    bench_suite::<MinimalEthSpec>(c, "minimal");
}

criterion_group!(benches, all_benches,);
criterion_main!(benches);
