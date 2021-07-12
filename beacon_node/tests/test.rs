#![cfg(test)]
#![recursion_limit = "256"]

use beacon_chain::StateSkipConfig;
use node_test_rig::{
    environment::{Environment, EnvironmentBuilder},
    eth2::types::StateId,
    testing_client_config, LocalBeaconNode,
};
use types::{EthSpec, MinimalEthSpec, Slot};

fn env_builder() -> EnvironmentBuilder<MinimalEthSpec> {
    EnvironmentBuilder::minimal()
}

fn build_node<E: EthSpec>(env: &mut Environment<E>) -> LocalBeaconNode<E> {
    let context = env.core_context();
    env.runtime()
        .block_on(LocalBeaconNode::production(
            context,
            testing_client_config(),
        ))
        .expect("should block until node created")
}

#[test]
fn http_server_genesis_state() {
    let mut env = env_builder()
        .null_logger()
        //.async_logger("debug", None)
        .expect("should build env logger")
        .multi_threaded_tokio_runtime()
        .expect("should start tokio runtime")
        .build()
        .expect("environment should build");

    // build a runtime guard

    let node = build_node(&mut env);

    let remote_node = node.remote_node().expect("should produce remote node");

    let api_state = env
        .runtime()
        .block_on(remote_node.get_debug_beacon_states(StateId::Slot(Slot::new(0))))
        .expect("should fetch state from http api")
        .unwrap()
        .data;

    let mut db_state = node
        .client
        .beacon_chain()
        .expect("client should have beacon chain")
        .state_at_slot(Slot::new(0), StateSkipConfig::WithStateRoots)
        .expect("should find state");
    db_state.drop_all_caches().unwrap();

    assert_eq!(
        api_state, db_state,
        "genesis state from api should match that from the DB"
    );

    env.fire_signal();
}
