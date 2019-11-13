#![cfg(test)]

use beacon_chain::{BeaconChain, BeaconChainTypes};
use node_test_rig::{
    environment::{Environment, EnvironmentBuilder},
    LocalBeaconNode,
};
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{
    test_utils::generate_deterministic_keypair, ChainSpec, Domain, EthSpec, MinimalEthSpec,
    Signature, Slot,
};

type E = MinimalEthSpec;

fn build_env() -> Environment<E> {
    EnvironmentBuilder::minimal()
        .null_logger()
        .expect("should build env logger")
        .single_thread_tokio_runtime()
        .expect("should start tokio runtime")
        .build()
        .expect("environment should build")
}

/// Returns the randao reveal for the given slot (assuming the given `beacon_chain` uses
/// deterministic keypairs).
fn get_randao_reveal<T: BeaconChainTypes>(
    beacon_chain: Arc<BeaconChain<T>>,
    slot: Slot,
    spec: &ChainSpec,
) -> Signature {
    let fork = beacon_chain.head().beacon_state.fork.clone();
    let proposer_index = beacon_chain
        .block_proposer(slot)
        .expect("should get proposer index");
    let keypair = generate_deterministic_keypair(proposer_index);
    let epoch = slot.epoch(E::slots_per_epoch());
    let message = epoch.tree_hash_root();
    let domain = spec.get_domain(epoch, Domain::Randao, &fork);
    Signature::new(&message, domain, &keypair.sk)
}

#[test]
fn validator_block_get() {
    let mut env = build_env();

    let spec = &E::default_spec();

    let node = LocalBeaconNode::production(env.core_context());
    let remote_node = node.remote_node().expect("should produce remote node");

    let beacon_chain = node
        .client
        .beacon_chain()
        .expect("client should have beacon chain");

    let slot = Slot::new(1);
    let randao_reveal = get_randao_reveal(beacon_chain.clone(), slot, spec);

    let block = env
        .runtime()
        .block_on(
            remote_node
                .http
                .validator()
                .block(slot, randao_reveal.clone()),
        )
        .expect("should fetch block from http api");

    let (expected_block, _state) = node
        .client
        .beacon_chain()
        .expect("client should have beacon chain")
        .produce_block(randao_reveal, slot)
        .expect("should produce block");

    assert_eq!(
        block, expected_block,
        "the block returned from the API should be as expected"
    );
}

#[test]
fn beacon_state() {
    let mut env = build_env();

    let node = LocalBeaconNode::production(env.core_context());
    let remote_node = node.remote_node().expect("should produce remote node");

    let (state_by_slot, root) = env
        .runtime()
        .block_on(remote_node.http.beacon().state_by_slot(Slot::new(0)))
        .expect("should fetch state from http api");

    let (state_by_root, root_2) = env
        .runtime()
        .block_on(remote_node.http.beacon().state_by_root(root))
        .expect("should fetch state from http api");

    let mut db_state = node
        .client
        .beacon_chain()
        .expect("client should have beacon chain")
        .state_at_slot(Slot::new(0))
        .expect("should find state");
    db_state.drop_all_caches();

    assert_eq!(
        root, root_2,
        "the two roots returned from the api should be identical"
    );
    assert_eq!(
        root,
        db_state.canonical_root(),
        "root from database should match that from the API"
    );
    assert_eq!(
        state_by_slot, db_state,
        "genesis state by slot from api should match that from the DB"
    );
    assert_eq!(
        state_by_root, db_state,
        "genesis state by root from api should match that from the DB"
    );
}

#[test]
fn beacon_block() {
    let mut env = build_env();

    let node = LocalBeaconNode::production(env.core_context());
    let remote_node = node.remote_node().expect("should produce remote node");

    let (block_by_slot, root) = env
        .runtime()
        .block_on(remote_node.http.beacon().block_by_slot(Slot::new(0)))
        .expect("should fetch block from http api");

    let (block_by_root, root_2) = env
        .runtime()
        .block_on(remote_node.http.beacon().block_by_root(root))
        .expect("should fetch block from http api");

    let db_block = node
        .client
        .beacon_chain()
        .expect("client should have beacon chain")
        .block_at_slot(Slot::new(0))
        .expect("should find block")
        .expect("block should not be none");

    assert_eq!(
        root, root_2,
        "the two roots returned from the api should be identical"
    );
    assert_eq!(
        root,
        db_block.canonical_root(),
        "root from database should match that from the API"
    );
    assert_eq!(
        block_by_slot, db_block,
        "genesis block by slot from api should match that from the DB"
    );
    assert_eq!(
        block_by_root, db_block,
        "genesis block by root from api should match that from the DB"
    );
}
