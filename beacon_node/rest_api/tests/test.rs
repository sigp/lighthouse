#![cfg(test)]

use beacon_chain::{BeaconChain, BeaconChainTypes};
use node_test_rig::{
    environment::{Environment, EnvironmentBuilder},
    testing_client_config, ClientConfig, ClientGenesis, LocalBeaconNode,
};
use remote_beacon_node::{PublishStatus, ValidatorDuty};
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{
    test_utils::generate_deterministic_keypair, BeaconBlock, ChainSpec, Domain, Epoch, EthSpec,
    MinimalEthSpec, PublicKey, RelativeEpoch, Signature, Slot,
};
use version;

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

fn build_node<E: EthSpec>(env: &mut Environment<E>, config: ClientConfig) -> LocalBeaconNode<E> {
    let context = env.core_context();
    env.runtime()
        .block_on(LocalBeaconNode::production(context, config))
        .expect("should block until node created")
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

/// Signs the given block (assuming the given `beacon_chain` uses deterministic keypairs).
fn sign_block<T: BeaconChainTypes>(
    beacon_chain: Arc<BeaconChain<T>>,
    block: &mut BeaconBlock<T::EthSpec>,
    spec: &ChainSpec,
) {
    let fork = beacon_chain.head().beacon_state.fork.clone();
    let proposer_index = beacon_chain
        .block_proposer(block.slot)
        .expect("should get proposer index");
    let keypair = generate_deterministic_keypair(proposer_index);
    block.sign(&keypair.sk, &fork, spec);
}

#[test]
fn validator_produce_attestation() {
    let mut env = build_env();

    let spec = &E::default_spec();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let beacon_chain = node
        .client
        .beacon_chain()
        .expect("client should have beacon chain");
    let state = beacon_chain.head().beacon_state.clone();

    let validator_index = 0;
    let duties = state
        .get_attestation_duties(validator_index, RelativeEpoch::Current)
        .expect("should have attestation duties cache")
        .expect("should have attestation duties");

    let mut attestation = env
        .runtime()
        .block_on(
            remote_node
                .http
                .validator()
                .produce_attestation(duties.slot, duties.index),
        )
        .expect("should fetch attestation from http api");

    assert_eq!(
        attestation.data.index, duties.index,
        "should have same index"
    );
    assert_eq!(attestation.data.slot, duties.slot, "should have same slot");
    assert_eq!(
        attestation.aggregation_bits.num_set_bits(),
        0,
        "should have empty aggregation bits"
    );

    let keypair = generate_deterministic_keypair(validator_index);

    // Fetch the duties again, but via HTTP for authenticity.
    let duties = env
        .runtime()
        .block_on(remote_node.http.validator().get_duties(
            attestation.data.slot.epoch(E::slots_per_epoch()),
            &[keypair.pk.clone()],
        ))
        .expect("should fetch duties from http api");
    let duties = &duties[0];

    // Try publishing the attestation without a signature, ensure it is flagged as invalid.
    let publish_status = env
        .runtime()
        .block_on(
            remote_node
                .http
                .validator()
                .publish_attestation(attestation.clone()),
        )
        .expect("should publish attestation");
    assert!(
        !publish_status.is_valid(),
        "the unsigned published attestation should not be valid"
    );

    attestation
        .sign(
            &keypair.sk,
            duties
                .attestation_committee_position
                .expect("should have committee position"),
            &state.fork,
            spec,
        )
        .expect("should sign attestation");

    // Try publishing the valid attestation.
    let publish_status = env
        .runtime()
        .block_on(
            remote_node
                .http
                .validator()
                .publish_attestation(attestation.clone()),
        )
        .expect("should publish attestation");
    assert!(
        publish_status.is_valid(),
        "the signed published attestation should be valid"
    );
}

#[test]
fn validator_duties_bulk() {
    let mut env = build_env();

    let spec = &E::default_spec();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let beacon_chain = node
        .client
        .beacon_chain()
        .expect("client should have beacon chain");

    let epoch = Epoch::new(0);

    let validators = beacon_chain
        .head()
        .beacon_state
        .validators
        .iter()
        .map(|v| v.pubkey.clone())
        .collect::<Vec<_>>();

    let duties = env
        .runtime()
        .block_on(
            remote_node
                .http
                .validator()
                .get_duties_bulk(epoch, &validators),
        )
        .expect("should fetch duties from http api");

    check_duties(duties, epoch, validators, beacon_chain, spec);
}

#[test]
fn validator_duties() {
    let mut env = build_env();

    let spec = &E::default_spec();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let beacon_chain = node
        .client
        .beacon_chain()
        .expect("client should have beacon chain");

    let mut epoch = Epoch::new(0);

    let validators = beacon_chain
        .head()
        .beacon_state
        .validators
        .iter()
        .map(|v| v.pubkey.clone())
        .collect::<Vec<_>>();

    let duties = env
        .runtime()
        .block_on(remote_node.http.validator().get_duties(epoch, &validators))
        .expect("should fetch duties from http api");

    // 1. Check at the current epoch.
    check_duties(
        duties,
        epoch,
        validators.clone(),
        beacon_chain.clone(),
        spec,
    );

    epoch += 4;
    let duties = env
        .runtime()
        .block_on(remote_node.http.validator().get_duties(epoch, &validators))
        .expect("should fetch duties from http api");

    // 2. Check with a long skip forward.
    check_duties(duties, epoch, validators, beacon_chain, spec);

    // TODO: test an epoch in the past. Blocked because the `LocalBeaconNode` cannot produce a
    // chain, yet.
}

fn check_duties<T: BeaconChainTypes>(
    duties: Vec<ValidatorDuty>,
    epoch: Epoch,
    validators: Vec<PublicKey>,
    beacon_chain: Arc<BeaconChain<T>>,
    spec: &ChainSpec,
) {
    assert_eq!(
        validators.len(),
        duties.len(),
        "there should be a duty for each validator"
    );

    let state = beacon_chain
        .state_at_slot(epoch.start_slot(T::EthSpec::slots_per_epoch()))
        .expect("should get state at slot");

    validators
        .iter()
        .zip(duties.iter())
        .for_each(|(validator, duty)| {
            assert_eq!(*validator, duty.validator_pubkey, "pubkey should match");

            let validator_index = state
                .get_validator_index(validator)
                .expect("should have pubkey cache")
                .expect("pubkey should exist");

            let attestation_duty = state
                .get_attestation_duties(validator_index, RelativeEpoch::Current)
                .expect("should have attestation duties cache")
                .expect("should have attestation duties");

            assert_eq!(
                Some(attestation_duty.slot),
                duty.attestation_slot,
                "attestation slot should match"
            );

            assert_eq!(
                Some(attestation_duty.index),
                duty.attestation_committee_index,
                "attestation index should match"
            );

            if let Some(slot) = duty.block_proposal_slot {
                let expected_proposer = state
                    .get_beacon_proposer_index(slot, spec)
                    .expect("should know proposer");
                assert_eq!(
                    expected_proposer, validator_index,
                    "should get correct proposal slot"
                );
            } else {
                epoch.slot_iter(E::slots_per_epoch()).for_each(|slot| {
                    let slot_proposer = state
                        .get_beacon_proposer_index(slot, spec)
                        .expect("should know proposer");
                    assert!(
                        slot_proposer != validator_index,
                        "validator should not have proposal slot in this epoch"
                    )
                })
            }
        });
}

#[test]
fn validator_block_post() {
    let mut env = build_env();

    let spec = &E::default_spec();

    let mut config = testing_client_config();
    config.genesis = ClientGenesis::Interop {
        validator_count: 8,
        genesis_time: 13_371_337,
    };

    let node = build_node(&mut env, config);
    let remote_node = node.remote_node().expect("should produce remote node");

    let beacon_chain = node
        .client
        .beacon_chain()
        .expect("client should have beacon chain");

    let slot = Slot::new(1);
    let randao_reveal = get_randao_reveal(beacon_chain.clone(), slot, spec);

    let mut block = env
        .runtime()
        .block_on(
            remote_node
                .http
                .validator()
                .produce_block(slot, randao_reveal.clone()),
        )
        .expect("should fetch block from http api");

    // Try publishing the block without a signature, ensure it is flagged as invalid.
    let publish_status = env
        .runtime()
        .block_on(remote_node.http.validator().publish_block(block.clone()))
        .expect("should publish block");
    if cfg!(not(feature = "fake_crypto")) {
        assert!(
            !publish_status.is_valid(),
            "the unsigned published block should not be valid"
        );
    }

    sign_block(beacon_chain.clone(), &mut block, spec);
    let block_root = block.canonical_root();

    let publish_status = env
        .runtime()
        .block_on(remote_node.http.validator().publish_block(block.clone()))
        .expect("should publish block");

    if cfg!(not(feature = "fake_crypto")) {
        assert_eq!(
            publish_status,
            PublishStatus::Valid,
            "the signed published block should be valid"
        );
    }

    let head = env
        .runtime()
        .block_on(remote_node.http.beacon().get_head())
        .expect("should get head");

    assert_eq!(
        head.block_root, block_root,
        "the published block should become the head block"
    );
}

#[test]
fn validator_block_get() {
    let mut env = build_env();

    let spec = &E::default_spec();

    let node = build_node(&mut env, testing_client_config());
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
                .produce_block(slot, randao_reveal.clone()),
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

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let (state_by_slot, root) = env
        .runtime()
        .block_on(remote_node.http.beacon().get_state_by_slot(Slot::new(0)))
        .expect("should fetch state from http api");

    let (state_by_root, root_2) = env
        .runtime()
        .block_on(remote_node.http.beacon().get_state_by_root(root))
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

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let (block_by_slot, root) = env
        .runtime()
        .block_on(remote_node.http.beacon().get_block_by_slot(Slot::new(0)))
        .expect("should fetch block from http api");

    let (block_by_root, root_2) = env
        .runtime()
        .block_on(remote_node.http.beacon().get_block_by_root(root))
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

#[test]
fn genesis_time() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let genesis_time = env
        .runtime()
        .block_on(remote_node.http.beacon().get_genesis_time())
        .expect("should fetch genesis time from http api");

    assert_eq!(
        node.client
            .beacon_chain()
            .expect("should have beacon chain")
            .head()
            .beacon_state
            .genesis_time,
        genesis_time,
        "should match genesis time from head state"
    );
}

#[test]
fn fork() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let fork = env
        .runtime()
        .block_on(remote_node.http.beacon().get_fork())
        .expect("should fetch from http api");

    assert_eq!(
        node.client
            .beacon_chain()
            .expect("should have beacon chain")
            .head()
            .beacon_state
            .fork,
        fork,
        "should match head state"
    );
}

#[test]
fn eth2_config() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let eth2_config = env
        .runtime()
        .block_on(remote_node.http.spec().get_eth2_config())
        .expect("should fetch eth2 config from http api");

    // TODO: check the entire eth2_config, not just the spec.

    assert_eq!(
        node.client
            .beacon_chain()
            .expect("should have beacon chain")
            .spec,
        eth2_config.spec,
        "should match genesis time from head state"
    );
}

#[test]
fn get_version() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let version = env
        .runtime()
        .block_on(remote_node.http.node().get_version())
        .expect("should fetch eth2 config from http api");

    assert_eq!(version::version(), version, "result should be as expected");
}
