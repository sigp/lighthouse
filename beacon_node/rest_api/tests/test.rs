#![cfg(test)]

#[macro_use]
extern crate assert_matches;

use beacon_chain::{BeaconChain, BeaconChainTypes, StateSkipConfig};
use node_test_rig::{
    environment::{Environment, EnvironmentBuilder},
    testing_client_config, ClientConfig, ClientGenesis, LocalBeaconNode,
};
use remote_beacon_node::{
    Committee, HeadBeaconBlock, PersistedOperationPool, PublishStatus, ValidatorResponse,
};
use rest_types::ValidatorDutyBytes;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{
    test_utils::{
        build_double_vote_attester_slashing, build_proposer_slashing,
        generate_deterministic_keypair, AttesterSlashingTestTask, ProposerSlashingTestTask,
    },
    BeaconBlock, BeaconState, ChainSpec, Domain, Epoch, EthSpec, MinimalEthSpec, PublicKey,
    RelativeEpoch, Signature, SignedAggregateAndProof, SignedBeaconBlock, SignedRoot, Slot,
    SubnetId, Validator,
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
    let head = beacon_chain.head().expect("should get head");
    let fork = head.beacon_state.fork;
    let genesis_validators_root = head.beacon_state.genesis_validators_root;
    let proposer_index = beacon_chain
        .block_proposer(slot)
        .expect("should get proposer index");
    let keypair = generate_deterministic_keypair(proposer_index);
    let epoch = slot.epoch(E::slots_per_epoch());
    let domain = spec.get_domain(epoch, Domain::Randao, &fork, genesis_validators_root);
    let message = epoch.signing_root(domain);
    Signature::new(message.as_bytes(), &keypair.sk)
}

/// Signs the given block (assuming the given `beacon_chain` uses deterministic keypairs).
fn sign_block<T: BeaconChainTypes>(
    beacon_chain: Arc<BeaconChain<T>>,
    block: BeaconBlock<T::EthSpec>,
    spec: &ChainSpec,
) -> SignedBeaconBlock<T::EthSpec> {
    let head = beacon_chain.head().expect("should get head");
    let fork = head.beacon_state.fork;
    let genesis_validators_root = head.beacon_state.genesis_validators_root;
    let proposer_index = beacon_chain
        .block_proposer(block.slot)
        .expect("should get proposer index");
    let keypair = generate_deterministic_keypair(proposer_index);
    block.sign(&keypair.sk, &fork, genesis_validators_root, spec)
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
    let genesis_validators_root = beacon_chain.genesis_validators_root;
    let state = beacon_chain.head().expect("should get head").beacon_state;

    // Find a validator that has duties in the current slot of the chain.
    let mut validator_index = 0;
    let duties = loop {
        let duties = state
            .get_attestation_duties(validator_index, RelativeEpoch::Current)
            .expect("should have attestation duties cache")
            .expect("should have attestation duties");

        if duties.slot == node.client.beacon_chain().unwrap().slot().unwrap() {
            break duties;
        } else {
            validator_index += 1
        }
    };

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
    let committee_count = duties
        .committee_count_at_slot
        .expect("should have committee count");
    let subnet_id = SubnetId::compute_subnet::<E>(
        attestation.data.slot,
        attestation.data.index,
        committee_count,
        spec,
    )
    .unwrap();
    // Try publishing the attestation without a signature or a committee bit set, ensure it is
    // raises an error.
    let publish_status = env
        .runtime()
        .block_on(
            remote_node
                .http
                .validator()
                .publish_attestations(vec![(attestation.clone(), subnet_id)]),
        )
        .expect("should publish unsigned attestation");
    assert!(
        !publish_status.is_valid(),
        "the unsigned published attestation should be invalid"
    );

    // Set the aggregation bit.
    attestation
        .aggregation_bits
        .set(
            duties
                .attestation_committee_position
                .expect("should have committee position"),
            true,
        )
        .expect("should set attestation bit");

    // Try publishing with an aggreagation bit set, but an invalid signature.
    let publish_status = env
        .runtime()
        .block_on(
            remote_node
                .http
                .validator()
                .publish_attestations(vec![(attestation.clone(), subnet_id)]),
        )
        .expect("should publish attestation with invalid signature");
    assert!(
        !publish_status.is_valid(),
        "the unsigned published attestation should not be valid"
    );

    // Un-set the aggregation bit, so signing doesn't error.
    attestation
        .aggregation_bits
        .set(
            duties
                .attestation_committee_position
                .expect("should have committee position"),
            false,
        )
        .expect("should un-set attestation bit");

    attestation
        .sign(
            &keypair.sk,
            duties
                .attestation_committee_position
                .expect("should have committee position"),
            &state.fork,
            state.genesis_validators_root,
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
                .publish_attestations(vec![(attestation.clone(), subnet_id)]),
        )
        .expect("should publish attestation");
    assert!(
        publish_status.is_valid(),
        "the signed published attestation should be valid"
    );

    // Try obtaining an aggregated attestation with a matching attestation data to the previous
    // one.
    let aggregated_attestation = env
        .runtime()
        .block_on(
            remote_node
                .http
                .validator()
                .produce_aggregate_attestation(&attestation.data),
        )
        .expect("should fetch aggregated attestation from http api");

    let signed_aggregate_and_proof = SignedAggregateAndProof::from_aggregate(
        validator_index as u64,
        aggregated_attestation,
        None,
        &keypair.sk,
        &state.fork,
        genesis_validators_root,
        spec,
    );

    // Publish the signed aggregate.
    let publish_status = env
        .runtime()
        .block_on(
            remote_node
                .http
                .validator()
                .publish_aggregate_and_proof(vec![signed_aggregate_and_proof]),
        )
        .expect("should publish aggregate and proof");
    assert!(
        publish_status.is_valid(),
        "the signed aggregate and proof should be valid"
    );
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
        .expect("should get head")
        .beacon_state
        .validators
        .iter()
        .map(|v| (&v.pubkey).try_into().expect("pubkey should be valid"))
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
    duties: Vec<ValidatorDutyBytes>,
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

    let mut state = beacon_chain
        .state_at_slot(
            epoch.start_slot(T::EthSpec::slots_per_epoch()),
            StateSkipConfig::WithStateRoots,
        )
        .expect("should get state at slot");

    state.build_all_caches(spec).expect("should build caches");

    validators
        .iter()
        .zip(duties.iter())
        .for_each(|(validator, duty)| {
            assert_eq!(
                *validator,
                (&duty.validator_pubkey)
                    .try_into()
                    .expect("should be valid pubkey"),
                "pubkey should match"
            );

            let validator_index = state
                .get_validator_index(&validator.clone().into())
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

            if !duty.block_proposal_slots.is_empty() {
                for slot in &duty.block_proposal_slots {
                    let expected_proposer = state
                        .get_beacon_proposer_index(*slot, spec)
                        .expect("should know proposer");
                    assert_eq!(
                        expected_proposer, validator_index,
                        "should get correct proposal slot"
                    );
                }
            } else {
                epoch.slot_iter(E::slots_per_epoch()).for_each(|slot| {
                    let slot_proposer = state
                        .get_beacon_proposer_index(slot, spec)
                        .expect("should know proposer");
                    assert_ne!(
                        slot_proposer, validator_index,
                        "validator should not have proposal slot in this epoch"
                    )
                })
            }
        });

    // Validator duties should include a proposer for every slot of the epoch.
    let mut all_proposer_slots: Vec<Slot> = duties
        .iter()
        .flat_map(|duty| duty.block_proposal_slots.clone())
        .collect();
    all_proposer_slots.sort();

    let all_slots: Vec<Slot> = epoch.slot_iter(E::slots_per_epoch()).collect();
    assert_eq!(all_proposer_slots, all_slots);
}

#[test]
fn validator_block_post() {
    let mut env = build_env();

    let spec = &E::default_spec();

    let two_slots_secs = (spec.milliseconds_per_slot / 1_000) * 2;

    let mut config = testing_client_config();
    config.genesis = ClientGenesis::Interop {
        validator_count: 8,
        genesis_time: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - two_slots_secs,
    };

    let node = build_node(&mut env, config);
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
                .produce_block(slot, randao_reveal),
        )
        .expect("should fetch block from http api");

    // Try publishing the block without a signature, ensure it is flagged as invalid.
    let empty_sig_block = SignedBeaconBlock {
        message: block.clone(),
        signature: Signature::empty_signature(),
    };
    let publish_status = env
        .runtime()
        .block_on(remote_node.http.validator().publish_block(empty_sig_block))
        .expect("should publish block");
    if cfg!(not(feature = "fake_crypto")) {
        assert!(
            !publish_status.is_valid(),
            "the unsigned published block should not be valid"
        );
    }

    let signed_block = sign_block(beacon_chain.clone(), block, spec);
    let block_root = signed_block.canonical_root();

    let publish_status = env
        .runtime()
        .block_on(remote_node.http.validator().publish_block(signed_block))
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

    // Note: this heads check is not super useful for this test, however it is include so it get
    // _some_ testing. If you remove this call, make sure it's tested somewhere else.
    let heads = env
        .runtime()
        .block_on(remote_node.http.beacon().get_heads())
        .expect("should get heads");

    assert_eq!(heads.len(), 1, "there should be only one head");
    assert_eq!(
        heads,
        vec![HeadBeaconBlock {
            beacon_block_root: head.block_root,
            beacon_block_slot: head.slot,
        }],
        "there should be only one head"
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
    let randao_reveal = get_randao_reveal(beacon_chain, slot, spec);

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
        .state_at_slot(Slot::new(0), StateSkipConfig::WithStateRoots)
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
            .expect("should get head")
            .beacon_state
            .genesis_time,
        genesis_time,
        "should match genesis time from head state"
    );
}

#[test]
fn genesis_validators_root() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let genesis_validators_root = env
        .runtime()
        .block_on(remote_node.http.beacon().get_genesis_validators_root())
        .expect("should fetch genesis time from http api");

    assert_eq!(
        node.client
            .beacon_chain()
            .expect("should have beacon chain")
            .head()
            .expect("should get head")
            .beacon_state
            .genesis_validators_root,
        genesis_validators_root,
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
            .expect("should get head")
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

#[test]
fn get_genesis_state_root() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let slot = Slot::new(0);

    let result = env
        .runtime()
        .block_on(remote_node.http.beacon().get_state_root(slot))
        .expect("should fetch from http api");

    let expected = node
        .client
        .beacon_chain()
        .expect("should have beacon chain")
        .rev_iter_state_roots()
        .expect("should get iter")
        .map(Result::unwrap)
        .find(|(_cur_root, cur_slot)| slot == *cur_slot)
        .map(|(cur_root, _)| cur_root)
        .expect("chain should have state root at slot");

    assert_eq!(result, expected, "result should be as expected");
}

#[test]
fn get_genesis_block_root() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let slot = Slot::new(0);

    let result = env
        .runtime()
        .block_on(remote_node.http.beacon().get_block_root(slot))
        .expect("should fetch from http api");

    let expected = node
        .client
        .beacon_chain()
        .expect("should have beacon chain")
        .rev_iter_block_roots()
        .expect("should get iter")
        .map(Result::unwrap)
        .find(|(_cur_root, cur_slot)| slot == *cur_slot)
        .map(|(cur_root, _)| cur_root)
        .expect("chain should have state root at slot");

    assert_eq!(result, expected, "result should be as expected");
}

#[test]
fn get_validators() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");
    let chain = node
        .client
        .beacon_chain()
        .expect("node should have beacon chain");
    let state = &chain.head().expect("should get head").beacon_state;

    let validators = state.validators.iter().take(2).collect::<Vec<_>>();
    let pubkeys = validators
        .iter()
        .map(|v| (&v.pubkey).try_into().expect("should decode pubkey bytes"))
        .collect();

    let result = env
        .runtime()
        .block_on(remote_node.http.beacon().get_validators(pubkeys, None))
        .expect("should fetch from http api");

    result
        .iter()
        .zip(validators.iter())
        .for_each(|(response, validator)| compare_validator_response(state, response, validator));
}

#[test]
fn get_all_validators() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");
    let chain = node
        .client
        .beacon_chain()
        .expect("node should have beacon chain");
    let state = &chain.head().expect("should get head").beacon_state;

    let result = env
        .runtime()
        .block_on(remote_node.http.beacon().get_all_validators(None))
        .expect("should fetch from http api");

    result
        .iter()
        .zip(state.validators.iter())
        .for_each(|(response, validator)| compare_validator_response(state, response, validator));
}

#[test]
fn get_active_validators() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");
    let chain = node
        .client
        .beacon_chain()
        .expect("node should have beacon chain");
    let state = &chain.head().expect("should get head").beacon_state;

    let result = env
        .runtime()
        .block_on(remote_node.http.beacon().get_active_validators(None))
        .expect("should fetch from http api");

    /*
     * This test isn't comprehensive because all of the validators in the state are active (i.e.,
     * there is no one to exclude.
     *
     * This should be fixed once we can generate more interesting scenarios with the
     * `NodeTestRig`.
     */

    let validators = state
        .validators
        .iter()
        .filter(|validator| validator.is_active_at(state.current_epoch()));

    result
        .iter()
        .zip(validators)
        .for_each(|(response, validator)| compare_validator_response(state, response, validator));
}

#[test]
fn get_committees() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");
    let chain = node
        .client
        .beacon_chain()
        .expect("node should have beacon chain");

    let epoch = Epoch::new(0);

    let result = env
        .runtime()
        .block_on(remote_node.http.beacon().get_committees(epoch))
        .expect("should fetch from http api");

    let expected = chain
        .head()
        .expect("should get head")
        .beacon_state
        .get_beacon_committees_at_epoch(RelativeEpoch::Current)
        .expect("should get committees")
        .iter()
        .map(|c| Committee {
            slot: c.slot,
            index: c.index,
            committee: c.committee.to_vec(),
        })
        .collect::<Vec<_>>();

    assert_eq!(result, expected, "result should be as expected");
}

#[test]
fn get_fork_choice() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let fork_choice = env
        .runtime()
        .block_on(remote_node.http.advanced().get_fork_choice())
        .expect("should not error when getting fork choice");

    assert_eq!(
        fork_choice,
        *node
            .client
            .beacon_chain()
            .expect("node should have beacon chain")
            .fork_choice
            .read()
            .proto_array()
            .core_proto_array(),
        "result should be as expected"
    );
}

#[test]
fn get_operation_pool() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    let result = env
        .runtime()
        .block_on(remote_node.http.advanced().get_operation_pool())
        .expect("should not error when getting fork choice");

    let expected = PersistedOperationPool::from_operation_pool(
        &node
            .client
            .beacon_chain()
            .expect("node should have chain")
            .op_pool,
    );

    assert_eq!(result, expected, "result should be as expected");
}

fn compare_validator_response<T: EthSpec>(
    state: &BeaconState<T>,
    response: &ValidatorResponse,
    validator: &Validator,
) {
    let response_validator = response.validator.clone().expect("should have validator");
    let i = response
        .validator_index
        .expect("should have validator index");
    let balance = response.balance.expect("should have balance");

    assert_eq!(response.pubkey, validator.pubkey, "pubkey");
    assert_eq!(response_validator, *validator, "validator");
    assert_eq!(state.balances[i], balance, "balances");
    assert_eq!(state.validators[i], *validator, "validator index");
}

#[test]
fn proposer_slashing() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");
    let chain = node
        .client
        .beacon_chain()
        .expect("node should have beacon chain");

    let state = chain
        .head()
        .expect("should have retrieved state")
        .beacon_state;

    let spec = &chain.spec;

    // Check that there are no proposer slashings before insertion
    let (proposer_slashings, _attester_slashings) = chain.op_pool.get_slashings(&state, spec);
    assert_eq!(proposer_slashings.len(), 0);

    let slot = state.slot;
    let proposer_index = chain
        .block_proposer(slot)
        .expect("should get proposer index");
    let keypair = generate_deterministic_keypair(proposer_index);
    let key = &keypair.sk;
    let fork = &state.fork;
    let proposer_slashing = build_proposer_slashing::<E>(
        ProposerSlashingTestTask::Valid,
        proposer_index as u64,
        &key,
        fork,
        state.genesis_validators_root,
        spec,
    );

    let result = env
        .runtime()
        .block_on(
            remote_node
                .http
                .beacon()
                .proposer_slashing(proposer_slashing.clone()),
        )
        .expect("should fetch from http api");
    assert!(result, true);

    // Length should be just one as we've inserted only one proposer slashing
    let (proposer_slashings, _attester_slashings) = chain.op_pool.get_slashings(&state, spec);
    assert_eq!(proposer_slashings.len(), 1);
    assert_eq!(proposer_slashing.clone(), proposer_slashings[0]);

    let mut invalid_proposer_slashing = build_proposer_slashing::<E>(
        ProposerSlashingTestTask::Valid,
        proposer_index as u64,
        &key,
        fork,
        state.genesis_validators_root,
        spec,
    );
    invalid_proposer_slashing.signed_header_2 = invalid_proposer_slashing.signed_header_1.clone();

    let result = env.runtime().block_on(
        remote_node
            .http
            .beacon()
            .proposer_slashing(invalid_proposer_slashing),
    );
    assert!(result.is_err());

    // Length should still be one as we've inserted nothing since last time.
    let (proposer_slashings, _attester_slashings) = chain.op_pool.get_slashings(&state, spec);
    assert_eq!(proposer_slashings.len(), 1);
    assert_eq!(proposer_slashing, proposer_slashings[0]);
}

#[test]
fn attester_slashing() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");
    let chain = node
        .client
        .beacon_chain()
        .expect("node should have beacon chain");

    let state = chain
        .head()
        .expect("should have retrieved state")
        .beacon_state;
    let slot = state.slot;
    let spec = &chain.spec;

    let proposer_index = chain
        .block_proposer(slot)
        .expect("should get proposer index");
    let keypair = generate_deterministic_keypair(proposer_index);

    let secret_keys = vec![&keypair.sk];
    let validator_indices = vec![proposer_index as u64];
    let fork = &state.fork;

    // Checking there are no attester slashings before insertion
    let (_proposer_slashings, attester_slashings) = chain.op_pool.get_slashings(&state, spec);
    assert_eq!(attester_slashings.len(), 0);

    let attester_slashing = build_double_vote_attester_slashing(
        AttesterSlashingTestTask::Valid,
        &validator_indices[..],
        &secret_keys[..],
        fork,
        state.genesis_validators_root,
        spec,
    );

    let result = env
        .runtime()
        .block_on(
            remote_node
                .http
                .beacon()
                .attester_slashing(attester_slashing.clone()),
        )
        .expect("should fetch from http api");
    assert!(result, true);

    // Length should be just one as we've inserted only one attester slashing
    let (_proposer_slashings, attester_slashings) = chain.op_pool.get_slashings(&state, spec);
    assert_eq!(attester_slashings.len(), 1);
    assert_eq!(attester_slashing, attester_slashings[0]);

    // Building an invalid attester slashing
    let mut invalid_attester_slashing = build_double_vote_attester_slashing(
        AttesterSlashingTestTask::Valid,
        &validator_indices[..],
        &secret_keys[..],
        fork,
        state.genesis_validators_root,
        spec,
    );
    invalid_attester_slashing.attestation_2 = invalid_attester_slashing.attestation_1.clone();

    let result = env.runtime().block_on(
        remote_node
            .http
            .beacon()
            .attester_slashing(invalid_attester_slashing),
    );
    assert!(result.is_err());

    // Length should still be one as we've failed to insert the attester slashing.
    let (_proposer_slashings, attester_slashings) = chain.op_pool.get_slashings(&state, spec);
    assert_eq!(attester_slashings.len(), 1);
    assert_eq!(attester_slashing, attester_slashings[0]);
}

mod validator_attestation {
    use super::*;
    use http::StatusCode;
    use node_test_rig::environment::Environment;
    use remote_beacon_node::{Error::DidNotSucceed, HttpClient};
    use types::{Attestation, AttestationDuty, MinimalEthSpec};
    use url::Url;

    fn setup() -> (
        Environment<MinimalEthSpec>,
        LocalBeaconNode<MinimalEthSpec>,
        HttpClient<MinimalEthSpec>,
        Url,
        AttestationDuty,
    ) {
        let mut env = build_env();
        let node = build_node(&mut env, testing_client_config());
        let remote_node = node.remote_node().expect("should produce remote node");
        let client = remote_node.http.clone();
        let socket_addr = node
            .client
            .http_listen_addr()
            .expect("A remote beacon node must have a http server");
        let url = Url::parse(&format!(
            "http://{}:{}/validator/attestation",
            socket_addr.ip(),
            socket_addr.port()
        ))
        .expect("should be valid endpoint");

        // Find a validator that has duties in the current slot of the chain.
        let mut validator_index = 0;
        let beacon_chain = node
            .client
            .beacon_chain()
            .expect("client should have beacon chain");
        let state = beacon_chain.head().expect("should get head").beacon_state;
        let duties = loop {
            let duties = state
                .get_attestation_duties(validator_index, RelativeEpoch::Current)
                .expect("should have attestation duties cache")
                .expect("should have attestation duties");

            if duties.slot == node.client.beacon_chain().unwrap().slot().unwrap() {
                break duties;
            } else {
                validator_index += 1
            }
        };

        (env, node, client, url, duties)
    }

    #[test]
    fn requires_query_parameters() {
        let (mut env, _node, client, url, _duties) = setup();

        let attestation = env.runtime().block_on(
            // query parameters are missing
            client.json_get::<Attestation<MinimalEthSpec>>(url.clone(), vec![]),
        );

        assert_matches!(
            attestation.expect_err("should not succeed"),
            DidNotSucceed { status, body } => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(body, "URL query must be valid and contain at least one of the following keys: [\"slot\"]".to_owned());
            }
        );
    }

    #[test]
    fn requires_slot() {
        let (mut env, _node, client, url, duties) = setup();

        let attestation = env.runtime().block_on(
            // `slot` is missing
            client.json_get::<Attestation<MinimalEthSpec>>(
                url.clone(),
                vec![("committee_index".into(), format!("{}", duties.index))],
            ),
        );

        assert_matches!(
            attestation.expect_err("should not succeed"),
            DidNotSucceed { status, body } => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(body, "URL query must be valid and contain at least one of the following keys: [\"slot\"]".to_owned());
            }
        );
    }

    #[test]
    fn requires_committee_index() {
        let (mut env, _node, client, url, duties) = setup();

        let attestation = env.runtime().block_on(
            // `committee_index` is missing.
            client.json_get::<Attestation<MinimalEthSpec>>(
                url.clone(),
                vec![("slot".into(), format!("{}", duties.slot))],
            ),
        );

        assert_matches!(
            attestation.expect_err("should not succeed"),
            DidNotSucceed { status, body } => {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(body, "URL query must be valid and contain at least one of the following keys: [\"committee_index\"]".to_owned());
            }
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn get_health() {
    let mut env = build_env();

    let node = build_node(&mut env, testing_client_config());
    let remote_node = node.remote_node().expect("should produce remote node");

    env.runtime()
        .block_on(remote_node.http.node().get_health())
        .unwrap();
}
