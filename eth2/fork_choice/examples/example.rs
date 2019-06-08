use fork_choice::{test_utils::TestingForkChoiceBuilder, ForkChoice, OptimizedLMDGhost};
use std::sync::Arc;
use store::{MemoryStore, Store};
use types::{BeaconBlock, ChainSpec, EthSpec, FoundationEthSpec, Hash256};

fn main() {
    let validator_count = 16;
    let chain_length = 100;
    let repetitions = 50;

    let store = MemoryStore::open();
    let builder: TestingForkChoiceBuilder<MemoryStore, FoundationEthSpec> =
        TestingForkChoiceBuilder::new(validator_count, chain_length, Arc::new(store));

    let fork_choosers: Vec<OptimizedLMDGhost<MemoryStore, FoundationEthSpec>> = (0..repetitions)
        .into_iter()
        .map(|_| builder.build())
        .collect();

    let spec = &FoundationEthSpec::default_spec();

    println!("Running {} times...", repetitions);
    for fc in fork_choosers {
        do_thing(fc, &builder.chain, builder.genesis_root(), spec);
    }
}

#[inline(never)]
fn do_thing<F: ForkChoice<S>, S: Store>(
    mut fc: F,
    chain: &[(Hash256, BeaconBlock)],
    genesis_root: Hash256,
    spec: &ChainSpec,
) {
    for (root, block) in chain.iter().skip(1) {
        fc.add_block(block, root, spec).unwrap();
    }

    let _head = fc.find_head(&genesis_root, spec).unwrap();
}
