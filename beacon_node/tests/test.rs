#![cfg(test)]

use node_test_rig::{environment::EnvironmentBuilder, LocalBeaconNode};
use types::{EthSpec, Slot};

#[test]
fn http_server_minimal() {
    test_http_server(EnvironmentBuilder::minimal());
}

// TODO: add other spec configs.

fn test_http_server<E: EthSpec>(env_builder: EnvironmentBuilder<E>) {
    let mut env = env_builder
        .null_logger()
        .expect("should build env logger")
        .tokio_runtime()
        .expect("should start tokio runtime")
        .build()
        .expect("environment should build");

    let node = LocalBeaconNode::production(env.core_context());
    let remote_node = node.remote_node().expect("should produce remote node");

    let (api_state, _root) = env
        .runtime()
        .block_on(remote_node.http.beacon().state_at_slot(Slot::new(0)))
        .expect("should fetch state from http api");

    let mut db_state = node
        .client
        .beacon_chain()
        .expect("client should have beacon chain")
        .state_at_slot(Slot::new(0))
        .expect("should find state");
    db_state.drop_all_caches();

    assert_eq!(
        api_state, db_state,
        "genesis state from api should match that from the DB"
    );
}
