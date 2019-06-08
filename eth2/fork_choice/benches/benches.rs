use criterion::Criterion;
use criterion::{criterion_group, criterion_main, Benchmark};
use fork_choice::{test_utils::TestingForkChoiceBuilder, ForkChoice, OptimizedLMDGhost};
use std::sync::Arc;
use store::MemoryStore;
use types::{ChainSpec, EthSpec, MainnetEthSpec};

pub type TestedForkChoice<T, U> = OptimizedLMDGhost<T, U>;
pub type TestedEthSpec = MainnetEthSpec;

/// Helper function to setup a builder and spec.
fn setup(
    validator_count: usize,
    chain_length: usize,
) -> (
    TestingForkChoiceBuilder<MemoryStore, TestedEthSpec>,
    ChainSpec,
) {
    let store = MemoryStore::open();
    let builder: TestingForkChoiceBuilder<MemoryStore, TestedEthSpec> =
        TestingForkChoiceBuilder::new(validator_count, chain_length, Arc::new(store));
    let spec = TestedEthSpec::default_spec();

    (builder, spec)
}

/// Benches adding blocks to fork_choice.
fn add_block(c: &mut Criterion) {
    let validator_count = 16;
    let chain_length = 100;

    let (builder, spec) = setup(validator_count, chain_length);

    c.bench(
        &format!("{}_blocks", chain_length),
        Benchmark::new("add_blocks", move |b| {
            b.iter(|| {
                let mut fc = builder.build::<TestedForkChoice<MemoryStore, TestedEthSpec>>();
                for (root, block) in builder.chain.iter().skip(1) {
                    fc.add_block(block, root, &spec).unwrap();
                }
            })
        })
        .sample_size(10),
    );
}

/// Benches fork choice head finding.
fn find_head(c: &mut Criterion) {
    let validator_count = 16;
    let chain_length = 64 * 2;

    let (builder, spec) = setup(validator_count, chain_length);

    let mut fc = builder.build::<TestedForkChoice<MemoryStore, TestedEthSpec>>();
    for (root, block) in builder.chain.iter().skip(1) {
        fc.add_block(block, root, &spec).unwrap();
    }

    let head_root = builder.chain.last().unwrap().0;
    for i in 0..validator_count {
        fc.add_attestation(i as u64, &head_root, &spec).unwrap();
    }

    c.bench(
        &format!("{}_blocks", chain_length),
        Benchmark::new("find_head", move |b| {
            b.iter(|| fc.find_head(&builder.genesis_root(), &spec).unwrap())
        })
        .sample_size(10),
    );
}

criterion_group!(benches, add_block, find_head);
criterion_main!(benches);
