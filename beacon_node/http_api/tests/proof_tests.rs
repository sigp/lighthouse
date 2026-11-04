use beacon_chain::ChainConfig;
use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use eth2::types::{BlockId, StateId};
use http_api::test_utils::InteractiveTester;
use reqwest::StatusCode;
use tree_hash::TreeHash;
use types::{EthSpec, ForkName, Slot, Spec};

type E = Spec;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proof_endpoints_fulu_state_and_block_roots() {
    let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
    let tester = InteractiveTester::<E>::new(Some(spec), 8).await;
    let state = tester.harness.chain.head_beacon_state_cloned();
    assert_eq!(state.fork_name_unchecked(), ForkName::Fulu);

    let state_root = tester
        .client
        .get_beacon_states_root(StateId::Head)
        .await
        .unwrap()
        .unwrap()
        .data
        .root;
    let balance = tester
        .client
        .get_lighthouse_state_proof(StateId::Head, 41_781_441_855_488)
        .await
        .unwrap();
    assert_eq!(balance.version, ForkName::Fulu);
    assert_eq!(balance.data.root, state_root);
    assert!(balance.data.verify());
    let validator = tester
        .client
        .get_lighthouse_state_proof(StateId::Head, 1_319_413_953_331_200)
        .await
        .unwrap();
    assert_eq!(
        validator.data.leaf,
        state.validators().get(0).unwrap().pubkey.tree_hash_root()
    );
    assert_eq!(validator.data.root, state_root);
    assert!(validator.data.verify());

    let block = tester
        .client
        .get_lighthouse_block_proof(BlockId::Head, 11)
        .await
        .unwrap();
    assert_eq!(block.data.leaf, state_root);
    assert_eq!(block.data.witnesses.len(), 3);
    assert!(block.data.verify());
    let header = tester
        .client
        .get_beacon_headers_block_id(BlockId::Head)
        .await
        .unwrap()
        .unwrap()
        .data;
    assert_eq!(block.data.root, header.root);

    let by_root = tester
        .client
        .get_lighthouse_state_proof(StateId::Root(state_root), 41_781_441_855_488)
        .await
        .unwrap();
    assert_eq!(by_root.data, balance.data);
    let genesis = tester
        .client
        .get_lighthouse_state_proof(StateId::Genesis, 1)
        .await
        .unwrap();
    assert!(genesis.finalized);
    assert!(genesis.data.verify());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proof_endpoints_reject_invalid_and_missing_data() {
    let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
    let tester = InteractiveTester::<E>::new(Some(spec), 8).await;
    for gindex in [0, u64::MAX, 1_319_413_953_331_200 + 8 * 8] {
        let error = tester
            .client
            .get_lighthouse_state_proof(StateId::Head, gindex)
            .await
            .unwrap_err();
        assert_eq!(error.status(), Some(StatusCode::BAD_REQUEST));
    }
    let error = tester
        .client
        .get_lighthouse_block_proof(BlockId::Head, 16)
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(StatusCode::BAD_REQUEST));
    let error = tester
        .client
        .get_lighthouse_block_proof(BlockId::Slot(999u64.into()), 11)
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(StatusCode::NOT_FOUND));
    let error = tester
        .client
        .get_lighthouse_state_proof(StateId::Root(types::Hash256::repeat_byte(0xff)), 1)
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(StatusCode::NOT_FOUND));
    for query in ["", "gindex=-1", "gindex=invalid", "gindex=11&gindex=12"] {
        let url = tester
            .client
            .server()
            .expose_full()
            .join(&format!("lighthouse/beacon/states/head/proof?{query}"))
            .unwrap();
        let response = reqwest::get(url).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proof_endpoints_reject_progressive_state_layouts() {
    let spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
    // Gloas genesis requires a nonempty attestation committee at every slot in the epoch.
    let validator_count = E::slots_per_epoch() as usize;
    let tester = InteractiveTester::<E>::new(Some(spec), validator_count).await;
    let error = tester
        .client
        .get_lighthouse_state_proof(StateId::Head, 41_781_441_855_488)
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(StatusCode::BAD_REQUEST));
    let root = tester
        .client
        .get_lighthouse_state_proof(StateId::Head, 1)
        .await
        .unwrap();
    assert!(root.data.verify());
    let block = tester
        .client
        .get_lighthouse_block_proof(BlockId::Head, 11)
        .await
        .unwrap();
    assert!(block.data.verify());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proof_endpoints_for_an_earlier_slot_use_its_state_root() {
    let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
    let tester = InteractiveTester::<E>::new(Some(spec), 24).await;
    let harness = &tester.harness;
    harness
        .mock_execution_layer
        .as_ref()
        .unwrap()
        .server
        .all_payloads_valid();
    harness.advance_slot();
    harness
        .extend_chain(
            3,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let slot = Slot::new(2);
    let state = tester
        .client
        .get_lighthouse_state_proof(StateId::Slot(slot), 41_781_441_855_488)
        .await
        .unwrap();
    let block = tester
        .client
        .get_lighthouse_block_proof(BlockId::Slot(slot), 11)
        .await
        .unwrap();
    assert!(state.data.verify());
    assert!(block.data.verify());
    assert_eq!(state.data.root, block.data.leaf);
    assert!(!state.execution_optimistic);
    let by_root = tester
        .client
        .get_lighthouse_state_proof(StateId::Root(state.data.root), state.data.gindex)
        .await
        .unwrap();
    assert_eq!(by_root.data, state.data);
    let head = tester
        .client
        .get_lighthouse_state_proof(StateId::Head, state.data.gindex)
        .await
        .unwrap();
    assert_ne!(head.data.root, state.data.root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proof_endpoints_for_finalized_cold_states_and_pruned_history() {
    let validator_count = 24;
    let spec = ForkName::Fulu.make_genesis_spec(E::default_spec());
    let tester = InteractiveTester::<E>::new_with_initializer_and_mutator(
        Some(spec),
        validator_count,
        Some(Box::new(move |builder| {
            builder
                .mock_execution_layer()
                .deterministic_keypairs(validator_count)
                .fresh_ephemeral_store()
                .chain_config(ChainConfig {
                    archive: true,
                    ..ChainConfig::default()
                })
        })),
        None,
        Default::default(),
        false,
        NodeCustodyType::Fullnode,
    )
    .await;
    let harness = &tester.harness;
    let mut genesis_state = harness.chain.head_beacon_state_cloned();
    let genesis_root = genesis_state.canonical_root().unwrap();
    harness
        .mock_execution_layer
        .as_ref()
        .unwrap()
        .server
        .all_payloads_valid();
    harness.advance_slot();
    harness
        .extend_chain(
            (6 * E::slots_per_epoch()) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Choose a slot between epoch boundaries so loading the cold state also exercises block replay.
    let slot = Slot::new(E::slots_per_epoch() + 1);
    assert!(slot < harness.chain.store.get_split_slot());
    let state_root = harness.chain.state_root_at_slot(slot).unwrap().unwrap();
    assert_eq!(
        harness
            .chain
            .store
            .load_cold_state_slot(&state_root)
            .unwrap(),
        Some(slot)
    );
    let block = tester
        .client
        .get_lighthouse_block_proof(BlockId::Slot(slot), 11)
        .await
        .unwrap();
    assert!(block.finalized);
    assert!(!block.execution_optimistic);
    assert!(block.data.verify());
    assert_eq!(block.data.leaf, state_root);

    for gindex in [41_781_441_855_488, 1_319_413_953_331_200] {
        let proof = tester
            .client
            .get_lighthouse_state_proof(StateId::Slot(slot), gindex)
            .await
            .unwrap();
        assert!(proof.finalized);
        assert!(!proof.execution_optimistic);
        assert_eq!(proof.version, ForkName::Fulu);
        assert_eq!(proof.data.root, block.data.leaf);
        assert!(proof.data.verify());
        let by_root = tester
            .client
            .get_lighthouse_state_proof(StateId::Root(state_root), gindex)
            .await
            .unwrap();
        assert!(by_root.finalized);
        assert_eq!(by_root.data, proof.data);
    }

    // Pruning in this ephemeral database must make the same history unavailable to the API.
    harness
        .chain
        .store
        .prune_historic_states(genesis_root, &genesis_state)
        .unwrap();
    for state_id in [StateId::Slot(slot), StateId::Root(state_root)] {
        let error = tester
            .client
            .get_lighthouse_state_proof(state_id, 41_781_441_855_488)
            .await
            .unwrap_err();
        assert_eq!(error.status(), Some(StatusCode::NOT_FOUND));
    }
}
