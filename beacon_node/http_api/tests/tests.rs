#![cfg(not(debug_assertions))] // Tests are too slow in debug.

use beacon_chain::{
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType},
    BeaconChain, StateSkipConfig,
};
use discv5::enr::{CombinedKey, EnrBuilder};
use environment::null_logger;
use eth2::{types::*, BeaconNodeHttpClient, Url};
use eth2_libp2p::{
    rpc::methods::MetaData,
    types::{EnrBitfield, SyncState},
    Enr, EnrExt, NetworkGlobals, PeerId,
};
use http_api::{Config, Context};
use network::NetworkMessage;
use state_processing::per_slot_processing;
use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tree_hash::TreeHash;
use types::{
    test_utils::generate_deterministic_keypairs, AggregateSignature, BeaconState, BitList, Domain,
    EthSpec, Hash256, Keypair, MainnetEthSpec, RelativeEpoch, SelectionProof, SignedRoot, Slot,
};
use warp::http::StatusCode;

type E = MainnetEthSpec;

const SLOTS_PER_EPOCH: u64 = 32;
const VALIDATOR_COUNT: usize = SLOTS_PER_EPOCH as usize;
const CHAIN_LENGTH: u64 = SLOTS_PER_EPOCH * 5;
const JUSTIFIED_EPOCH: u64 = 4;
const FINALIZED_EPOCH: u64 = 3;
const TCP_PORT: u16 = 42;
const UDP_PORT: u16 = 42;
const SEQ_NUMBER: u64 = 0;
const EXTERNAL_ADDR: &str = "/ip4/0.0.0.0/tcp/9000";

/// Skipping the slots around the epoch boundary allows us to check that we're obtaining states
/// from skipped slots for the finalized and justified checkpoints (instead of the state from the
/// block that those roots point to).
const SKIPPED_SLOTS: &[u64] = &[
    JUSTIFIED_EPOCH * SLOTS_PER_EPOCH - 1,
    JUSTIFIED_EPOCH * SLOTS_PER_EPOCH,
    FINALIZED_EPOCH * SLOTS_PER_EPOCH - 1,
    FINALIZED_EPOCH * SLOTS_PER_EPOCH,
];

struct ApiTester {
    chain: Arc<BeaconChain<EphemeralHarnessType<E>>>,
    client: BeaconNodeHttpClient,
    next_block: SignedBeaconBlock<E>,
    attestations: Vec<Attestation<E>>,
    attester_slashing: AttesterSlashing<E>,
    proposer_slashing: ProposerSlashing,
    voluntary_exit: SignedVoluntaryExit,
    _server_shutdown: oneshot::Sender<()>,
    validator_keypairs: Vec<Keypair>,
    network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
    local_enr: Enr,
    external_peer_id: PeerId,
}

impl ApiTester {
    pub fn new() -> Self {
        let mut harness = BeaconChainHarness::new(
            MainnetEthSpec,
            generate_deterministic_keypairs(VALIDATOR_COUNT),
        );

        harness.advance_slot();

        for _ in 0..CHAIN_LENGTH {
            let slot = harness.chain.slot().unwrap().as_u64();

            if !SKIPPED_SLOTS.contains(&slot) {
                harness.extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                );
            }

            harness.advance_slot();
        }

        let head = harness.chain.head().unwrap();

        assert_eq!(
            harness.chain.slot().unwrap(),
            head.beacon_block.slot() + 1,
            "precondition: current slot is one after head"
        );

        let (next_block, _next_state) =
            harness.make_block(head.beacon_state.clone(), harness.chain.slot().unwrap());

        let attestations = harness
            .get_unaggregated_attestations(
                &AttestationStrategy::AllValidators,
                &head.beacon_state,
                head.beacon_block_root,
                harness.chain.slot().unwrap(),
            )
            .into_iter()
            .map(|vec| vec.into_iter().map(|(attestation, _subnet_id)| attestation))
            .flatten()
            .collect::<Vec<_>>();

        assert!(
            !attestations.is_empty(),
            "precondition: attestations for testing"
        );

        let attester_slashing = harness.make_attester_slashing(vec![0, 1]);
        let proposer_slashing = harness.make_proposer_slashing(2);
        let voluntary_exit = harness.make_voluntary_exit(3, harness.chain.epoch().unwrap());

        // Changing this *after* the chain has been initialized is a bit cheeky, but it shouldn't
        // cause issue.
        //
        // This allows for testing voluntary exits without building out a massive chain.
        harness.chain.spec.shard_committee_period = 2;

        let chain = Arc::new(harness.chain);

        assert_eq!(
            chain.head_info().unwrap().finalized_checkpoint.epoch,
            3,
            "precondition: finality"
        );
        assert_eq!(
            chain
                .head_info()
                .unwrap()
                .current_justified_checkpoint
                .epoch,
            4,
            "precondition: justification"
        );

        let (network_tx, network_rx) = mpsc::unbounded_channel();

        let log = null_logger().unwrap();

        // Default metadata
        let meta_data = MetaData {
            seq_number: SEQ_NUMBER,
            attnets: EnrBitfield::<MainnetEthSpec>::default(),
        };
        let enr_key = CombinedKey::generate_secp256k1();
        let enr = EnrBuilder::new("v4").build(&enr_key).unwrap();
        let enr_clone = enr.clone();
        let network_globals = NetworkGlobals::new(enr, TCP_PORT, UDP_PORT, meta_data, vec![], &log);

        let peer_id = PeerId::random();
        network_globals.peers.write().connect_ingoing(
            &peer_id,
            EXTERNAL_ADDR.parse().unwrap(),
            None,
        );

        *network_globals.sync_state.write() = SyncState::Synced;

        let eth1_service =
            eth1::Service::new(eth1::Config::default(), log.clone(), chain.spec.clone());

        let context = Arc::new(Context {
            config: Config {
                enabled: true,
                listen_addr: Ipv4Addr::new(127, 0, 0, 1),
                listen_port: 0,
                allow_origin: None,
            },
            chain: Some(chain.clone()),
            network_tx: Some(network_tx),
            network_globals: Some(Arc::new(network_globals)),
            eth1_service: Some(eth1_service),
            log,
        });
        let ctx = context.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server_shutdown = async {
            // It's not really interesting why this triggered, just that it happened.
            let _ = shutdown_rx.await;
        };
        let (listening_socket, server) = http_api::serve(ctx, server_shutdown).unwrap();

        tokio::spawn(async { server.await });

        let client = BeaconNodeHttpClient::new(
            Url::parse(&format!(
                "http://{}:{}",
                listening_socket.ip(),
                listening_socket.port()
            ))
            .unwrap(),
        );

        Self {
            chain,
            client,
            next_block,
            attestations,
            attester_slashing,
            proposer_slashing,
            voluntary_exit,
            _server_shutdown: shutdown_tx,
            validator_keypairs: harness.validator_keypairs,
            network_rx,
            local_enr: enr_clone,
            external_peer_id: peer_id,
        }
    }

    fn skip_slots(self, count: u64) -> Self {
        for _ in 0..count {
            self.chain
                .slot_clock
                .set_slot(self.chain.slot().unwrap().as_u64() + 1);
        }

        self
    }

    fn interesting_state_ids(&self) -> Vec<StateId> {
        let mut ids = vec![
            StateId::Head,
            StateId::Genesis,
            StateId::Finalized,
            StateId::Justified,
            StateId::Slot(Slot::new(0)),
            StateId::Slot(Slot::new(32)),
            StateId::Slot(Slot::from(SKIPPED_SLOTS[0])),
            StateId::Slot(Slot::from(SKIPPED_SLOTS[1])),
            StateId::Slot(Slot::from(SKIPPED_SLOTS[2])),
            StateId::Slot(Slot::from(SKIPPED_SLOTS[3])),
            StateId::Root(Hash256::zero()),
        ];
        ids.push(StateId::Root(self.chain.head_info().unwrap().state_root));
        ids
    }

    fn interesting_block_ids(&self) -> Vec<BlockId> {
        let mut ids = vec![
            BlockId::Head,
            BlockId::Genesis,
            BlockId::Finalized,
            BlockId::Justified,
            BlockId::Slot(Slot::new(0)),
            BlockId::Slot(Slot::new(32)),
            BlockId::Slot(Slot::from(SKIPPED_SLOTS[0])),
            BlockId::Slot(Slot::from(SKIPPED_SLOTS[1])),
            BlockId::Slot(Slot::from(SKIPPED_SLOTS[2])),
            BlockId::Slot(Slot::from(SKIPPED_SLOTS[3])),
            BlockId::Root(Hash256::zero()),
        ];
        ids.push(BlockId::Root(self.chain.head_info().unwrap().block_root));
        ids
    }

    fn get_state(&self, state_id: StateId) -> Option<BeaconState<E>> {
        match state_id {
            StateId::Head => Some(self.chain.head().unwrap().beacon_state),
            StateId::Genesis => self
                .chain
                .get_state(&self.chain.genesis_state_root, None)
                .unwrap(),
            StateId::Finalized => {
                let finalized_slot = self
                    .chain
                    .head_info()
                    .unwrap()
                    .finalized_checkpoint
                    .epoch
                    .start_slot(E::slots_per_epoch());

                let root = self
                    .chain
                    .state_root_at_slot(finalized_slot)
                    .unwrap()
                    .unwrap();

                self.chain.get_state(&root, Some(finalized_slot)).unwrap()
            }
            StateId::Justified => {
                let justified_slot = self
                    .chain
                    .head_info()
                    .unwrap()
                    .current_justified_checkpoint
                    .epoch
                    .start_slot(E::slots_per_epoch());

                let root = self
                    .chain
                    .state_root_at_slot(justified_slot)
                    .unwrap()
                    .unwrap();

                self.chain.get_state(&root, Some(justified_slot)).unwrap()
            }
            StateId::Slot(slot) => {
                let root = self.chain.state_root_at_slot(slot).unwrap().unwrap();

                self.chain.get_state(&root, Some(slot)).unwrap()
            }
            StateId::Root(root) => self.chain.get_state(&root, None).unwrap(),
        }
    }

    pub async fn test_beacon_genesis(self) -> Self {
        let result = self.client.get_beacon_genesis().await.unwrap().data;

        let state = self.chain.head().unwrap().beacon_state;
        let expected = GenesisData {
            genesis_time: state.genesis_time,
            genesis_validators_root: state.genesis_validators_root,
            genesis_fork_version: self.chain.spec.genesis_fork_version,
        };

        assert_eq!(result, expected);

        self
    }

    pub async fn test_beacon_states_root(self) -> Self {
        for state_id in self.interesting_state_ids() {
            let result = self
                .client
                .get_beacon_states_root(state_id)
                .await
                .unwrap()
                .map(|res| res.data.root);

            let expected = match state_id {
                StateId::Head => Some(self.chain.head_info().unwrap().state_root),
                StateId::Genesis => Some(self.chain.genesis_state_root),
                StateId::Finalized => {
                    let finalized_slot = self
                        .chain
                        .head_info()
                        .unwrap()
                        .finalized_checkpoint
                        .epoch
                        .start_slot(E::slots_per_epoch());

                    self.chain.state_root_at_slot(finalized_slot).unwrap()
                }
                StateId::Justified => {
                    let justified_slot = self
                        .chain
                        .head_info()
                        .unwrap()
                        .current_justified_checkpoint
                        .epoch
                        .start_slot(E::slots_per_epoch());

                    self.chain.state_root_at_slot(justified_slot).unwrap()
                }
                StateId::Slot(slot) => self.chain.state_root_at_slot(slot).unwrap(),
                StateId::Root(root) => Some(root),
            };

            assert_eq!(result, expected, "{:?}", state_id);
        }

        self
    }

    pub async fn test_beacon_states_fork(self) -> Self {
        for state_id in self.interesting_state_ids() {
            let result = self
                .client
                .get_beacon_states_fork(state_id)
                .await
                .unwrap()
                .map(|res| res.data);

            let expected = self.get_state(state_id).map(|state| state.fork);

            assert_eq!(result, expected, "{:?}", state_id);
        }

        self
    }

    pub async fn test_beacon_states_finality_checkpoints(self) -> Self {
        for state_id in self.interesting_state_ids() {
            let result = self
                .client
                .get_beacon_states_finality_checkpoints(state_id)
                .await
                .unwrap()
                .map(|res| res.data);

            let expected = self
                .get_state(state_id)
                .map(|state| FinalityCheckpointsData {
                    previous_justified: state.previous_justified_checkpoint,
                    current_justified: state.current_justified_checkpoint,
                    finalized: state.finalized_checkpoint,
                });

            assert_eq!(result, expected, "{:?}", state_id);
        }

        self
    }

    pub async fn test_beacon_states_validators(self) -> Self {
        for state_id in self.interesting_state_ids() {
            for statuses in self.interesting_validator_statuses() {
                for validator_indices in self.interesting_validator_indices() {
                    let state_opt = self.get_state(state_id);
                    let validators: Vec<Validator> = match state_opt.as_ref() {
                        Some(state) => state.validators.clone().into(),
                        None => vec![],
                    };
                    let validator_index_ids = validator_indices
                        .iter()
                        .cloned()
                        .map(|i| ValidatorId::Index(i))
                        .collect::<Vec<ValidatorId>>();
                    let validator_pubkey_ids = validator_indices
                        .iter()
                        .cloned()
                        .map(|i| {
                            ValidatorId::PublicKey(
                                validators
                                    .get(i as usize)
                                    .map_or(PublicKeyBytes::empty(), |val| val.pubkey.clone()),
                            )
                        })
                        .collect::<Vec<ValidatorId>>();

                    let result_index_ids = self
                        .client
                        .get_beacon_states_validators(
                            state_id,
                            Some(validator_index_ids.as_slice()),
                            None,
                        )
                        .await
                        .unwrap()
                        .map(|res| res.data);

                    let result_pubkey_ids = self
                        .client
                        .get_beacon_states_validators(
                            state_id,
                            Some(validator_pubkey_ids.as_slice()),
                            None,
                        )
                        .await
                        .unwrap()
                        .map(|res| res.data);

                    let expected = state_opt.map(|state| {
                        let epoch = state.current_epoch();
                        let finalized_epoch = state.finalized_checkpoint.epoch;
                        let far_future_epoch = self.chain.spec.far_future_epoch;

                        let mut validators = Vec::with_capacity(validator_indices.len());

                        for i in validator_indices {
                            if i >= state.validators.len() as u64 {
                                continue;
                            }
                            let validator = state.validators[i as usize].clone();
                            let status = ValidatorStatus::from_validator(
                                Some(&validator),
                                epoch,
                                finalized_epoch,
                                far_future_epoch,
                            );
                            if statuses.contains(&status) || statuses.is_empty() {
                                validators.push(ValidatorData {
                                    index: i as u64,
                                    balance: state.balances[i as usize],
                                    status,
                                    validator,
                                });
                            }
                        }

                        validators
                    });

                    assert_eq!(result_index_ids, expected, "{:?}", state_id);
                    assert_eq!(result_pubkey_ids, expected, "{:?}", state_id);
                }
            }
        }

        self
    }

    pub async fn test_beacon_states_validator_id(self) -> Self {
        for state_id in self.interesting_state_ids() {
            let state_opt = self.get_state(state_id);
            let validators = match state_opt.as_ref() {
                Some(state) => state.validators.clone().into(),
                None => vec![],
            };

            for (i, validator) in validators.into_iter().enumerate() {
                let validator_ids = &[
                    ValidatorId::PublicKey(validator.pubkey.clone()),
                    ValidatorId::Index(i as u64),
                ];

                for validator_id in validator_ids {
                    let result = self
                        .client
                        .get_beacon_states_validator_id(state_id, validator_id)
                        .await
                        .unwrap()
                        .map(|res| res.data);

                    if result.is_none() && state_opt.is_none() {
                        continue;
                    }

                    let state = state_opt.as_ref().expect("result should be none");

                    let expected = {
                        let epoch = state.current_epoch();
                        let finalized_epoch = state.finalized_checkpoint.epoch;
                        let far_future_epoch = self.chain.spec.far_future_epoch;

                        ValidatorData {
                            index: i as u64,
                            balance: state.balances[i],
                            status: ValidatorStatus::from_validator(
                                Some(&validator),
                                epoch,
                                finalized_epoch,
                                far_future_epoch,
                            ),
                            validator: validator.clone(),
                        }
                    };

                    assert_eq!(result, Some(expected), "{:?}, {:?}", state_id, validator_id);
                }
            }
        }

        self
    }

    pub async fn test_beacon_states_committees(self) -> Self {
        for state_id in self.interesting_state_ids() {
            let mut state_opt = self.get_state(state_id);

            let epoch = state_opt
                .as_ref()
                .map(|state| state.current_epoch())
                .unwrap_or_else(|| Epoch::new(0));

            let results = self
                .client
                .get_beacon_states_committees(state_id, epoch, None, None)
                .await
                .unwrap()
                .map(|res| res.data);

            if results.is_none() && state_opt.is_none() {
                continue;
            }

            let state = state_opt.as_mut().expect("result should be none");
            state.build_all_committee_caches(&self.chain.spec).unwrap();
            let committees = state
                .get_beacon_committees_at_epoch(
                    RelativeEpoch::from_epoch(state.current_epoch(), epoch).unwrap(),
                )
                .unwrap();

            for (i, result) in results.unwrap().into_iter().enumerate() {
                let expected = &committees[i];

                assert_eq!(result.index, expected.index, "{}", state_id);
                assert_eq!(result.slot, expected.slot, "{}", state_id);
                assert_eq!(
                    result
                        .validators
                        .into_iter()
                        .map(|i| i as usize)
                        .collect::<Vec<_>>(),
                    expected.committee.to_vec(),
                    "{}",
                    state_id
                );
            }
        }

        self
    }

    fn get_block_root(&self, block_id: BlockId) -> Option<Hash256> {
        match block_id {
            BlockId::Head => Some(self.chain.head_info().unwrap().block_root),
            BlockId::Genesis => Some(self.chain.genesis_block_root),
            BlockId::Finalized => Some(self.chain.head_info().unwrap().finalized_checkpoint.root),
            BlockId::Justified => Some(
                self.chain
                    .head_info()
                    .unwrap()
                    .current_justified_checkpoint
                    .root,
            ),
            BlockId::Slot(slot) => self.chain.block_root_at_slot(slot).unwrap(),
            BlockId::Root(root) => Some(root),
        }
    }

    fn get_block(&self, block_id: BlockId) -> Option<SignedBeaconBlock<E>> {
        let root = self.get_block_root(block_id);
        root.and_then(|root| self.chain.get_block(&root).unwrap())
    }

    pub async fn test_beacon_headers_all_slots(self) -> Self {
        for slot in 0..CHAIN_LENGTH {
            let slot = Slot::from(slot);

            let result = self
                .client
                .get_beacon_headers(Some(slot), None)
                .await
                .unwrap()
                .map(|res| res.data);

            let root = self.chain.block_root_at_slot(slot).unwrap();

            if root.is_none() && result.is_none() {
                continue;
            }

            let root = root.unwrap();
            let block = self.chain.block_at_slot(slot).unwrap().unwrap();
            let header = BlockHeaderData {
                root,
                canonical: true,
                header: BlockHeaderAndSignature {
                    message: block.message.block_header(),
                    signature: block.signature.into(),
                },
            };
            let expected = vec![header];

            assert_eq!(result.unwrap(), expected, "slot {:?}", slot);
        }

        self
    }

    pub async fn test_beacon_headers_all_parents(self) -> Self {
        let mut roots = self
            .chain
            .rev_iter_block_roots()
            .unwrap()
            .map(Result::unwrap)
            .map(|(root, _slot)| root)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>();

        // The iterator natively returns duplicate roots for skipped slots.
        roots.dedup();

        for i in 1..roots.len() {
            let parent_root = roots[i - 1];
            let child_root = roots[i];

            let result = self
                .client
                .get_beacon_headers(None, Some(parent_root))
                .await
                .unwrap()
                .unwrap()
                .data;

            assert_eq!(result.len(), 1, "i {}", i);
            assert_eq!(result[0].root, child_root, "i {}", i);
        }

        self
    }

    pub async fn test_beacon_headers_block_id(self) -> Self {
        for block_id in self.interesting_block_ids() {
            let result = self
                .client
                .get_beacon_headers_block_id(block_id)
                .await
                .unwrap()
                .map(|res| res.data);

            let block_root_opt = self.get_block_root(block_id);

            let block_opt = block_root_opt.and_then(|root| self.chain.get_block(&root).unwrap());

            if block_opt.is_none() && result.is_none() {
                continue;
            }

            let result = result.unwrap();
            let block = block_opt.unwrap();
            let block_root = block_root_opt.unwrap();
            let canonical = self
                .chain
                .block_root_at_slot(block.slot())
                .unwrap()
                .map_or(false, |canonical| block_root == canonical);

            assert_eq!(result.canonical, canonical, "{:?}", block_id);
            assert_eq!(result.root, block_root, "{:?}", block_id);
            assert_eq!(
                result.header.message,
                block.message.block_header(),
                "{:?}",
                block_id
            );
            assert_eq!(
                result.header.signature,
                block.signature.into(),
                "{:?}",
                block_id
            );
        }

        self
    }

    pub async fn test_beacon_blocks_root(self) -> Self {
        for block_id in self.interesting_block_ids() {
            let result = self
                .client
                .get_beacon_blocks_root(block_id)
                .await
                .unwrap()
                .map(|res| res.data.root);

            let expected = self.get_block_root(block_id);

            assert_eq!(result, expected, "{:?}", block_id);
        }

        self
    }

    pub async fn test_post_beacon_blocks_valid(mut self) -> Self {
        let next_block = &self.next_block;

        self.client.post_beacon_blocks(next_block).await.unwrap();

        assert!(
            self.network_rx.try_recv().is_ok(),
            "valid blocks should be sent to network"
        );

        self
    }

    pub async fn test_post_beacon_blocks_invalid(mut self) -> Self {
        let mut next_block = self.next_block.clone();
        next_block.message.proposer_index += 1;

        assert!(self.client.post_beacon_blocks(&next_block).await.is_err());

        assert!(
            self.network_rx.try_recv().is_ok(),
            "invalid blocks should be sent to network"
        );

        self
    }

    pub async fn test_beacon_blocks(self) -> Self {
        for block_id in self.interesting_block_ids() {
            let result = self
                .client
                .get_beacon_blocks(block_id)
                .await
                .unwrap()
                .map(|res| res.data);

            let expected = self.get_block(block_id);

            assert_eq!(result, expected, "{:?}", block_id);
        }

        self
    }

    pub async fn test_beacon_blocks_attestations(self) -> Self {
        for block_id in self.interesting_block_ids() {
            let result = self
                .client
                .get_beacon_blocks_attestations(block_id)
                .await
                .unwrap()
                .map(|res| res.data);

            let expected = self
                .get_block(block_id)
                .map(|block| block.message.body.attestations.into());

            assert_eq!(result, expected, "{:?}", block_id);
        }

        self
    }

    pub async fn test_post_beacon_pool_attestations_valid(mut self) -> Self {
        for attestation in &self.attestations {
            self.client
                .post_beacon_pool_attestations(attestation)
                .await
                .unwrap();

            assert!(
                self.network_rx.try_recv().is_ok(),
                "valid attestation should be sent to network"
            );
        }

        self
    }

    pub async fn test_post_beacon_pool_attestations_invalid(mut self) -> Self {
        for attestation in &self.attestations {
            let mut attestation = attestation.clone();
            attestation.data.slot += 1;

            assert!(self
                .client
                .post_beacon_pool_attestations(&attestation)
                .await
                .is_err());

            assert!(
                self.network_rx.try_recv().is_err(),
                "invalid attestation should not be sent to network"
            );
        }

        self
    }

    pub async fn test_get_beacon_pool_attestations(self) -> Self {
        let result = self
            .client
            .get_beacon_pool_attestations()
            .await
            .unwrap()
            .data;

        let mut expected = self.chain.op_pool.get_all_attestations();
        expected.extend(self.chain.naive_aggregation_pool.read().iter().cloned());

        assert_eq!(result, expected);

        self
    }

    pub async fn test_post_beacon_pool_attester_slashings_valid(mut self) -> Self {
        self.client
            .post_beacon_pool_attester_slashings(&self.attester_slashing)
            .await
            .unwrap();

        assert!(
            self.network_rx.try_recv().is_ok(),
            "valid attester slashing should be sent to network"
        );

        self
    }

    pub async fn test_post_beacon_pool_attester_slashings_invalid(mut self) -> Self {
        let mut slashing = self.attester_slashing.clone();
        slashing.attestation_1.data.slot += 1;

        self.client
            .post_beacon_pool_attester_slashings(&slashing)
            .await
            .unwrap_err();

        assert!(
            self.network_rx.try_recv().is_err(),
            "invalid attester slashing should not be sent to network"
        );

        self
    }

    pub async fn test_get_beacon_pool_attester_slashings(self) -> Self {
        let result = self
            .client
            .get_beacon_pool_attester_slashings()
            .await
            .unwrap()
            .data;

        let expected = self.chain.op_pool.get_all_attester_slashings();

        assert_eq!(result, expected);

        self
    }

    pub async fn test_post_beacon_pool_proposer_slashings_valid(mut self) -> Self {
        self.client
            .post_beacon_pool_proposer_slashings(&self.proposer_slashing)
            .await
            .unwrap();

        assert!(
            self.network_rx.try_recv().is_ok(),
            "valid proposer slashing should be sent to network"
        );

        self
    }

    pub async fn test_post_beacon_pool_proposer_slashings_invalid(mut self) -> Self {
        let mut slashing = self.proposer_slashing.clone();
        slashing.signed_header_1.message.slot += 1;

        self.client
            .post_beacon_pool_proposer_slashings(&slashing)
            .await
            .unwrap_err();

        assert!(
            self.network_rx.try_recv().is_err(),
            "invalid proposer slashing should not be sent to network"
        );

        self
    }

    pub async fn test_get_beacon_pool_proposer_slashings(self) -> Self {
        let result = self
            .client
            .get_beacon_pool_proposer_slashings()
            .await
            .unwrap()
            .data;

        let expected = self.chain.op_pool.get_all_proposer_slashings();

        assert_eq!(result, expected);

        self
    }

    pub async fn test_post_beacon_pool_voluntary_exits_valid(mut self) -> Self {
        self.client
            .post_beacon_pool_voluntary_exits(&self.voluntary_exit)
            .await
            .unwrap();

        assert!(
            self.network_rx.try_recv().is_ok(),
            "valid exit should be sent to network"
        );

        self
    }

    pub async fn test_post_beacon_pool_voluntary_exits_invalid(mut self) -> Self {
        let mut exit = self.voluntary_exit.clone();
        exit.message.epoch += 1;

        self.client
            .post_beacon_pool_voluntary_exits(&exit)
            .await
            .unwrap_err();

        assert!(
            self.network_rx.try_recv().is_err(),
            "invalid exit should not be sent to network"
        );

        self
    }

    pub async fn test_get_beacon_pool_voluntary_exits(self) -> Self {
        let result = self
            .client
            .get_beacon_pool_voluntary_exits()
            .await
            .unwrap()
            .data;

        let expected = self.chain.op_pool.get_all_voluntary_exits();

        assert_eq!(result, expected);

        self
    }

    pub async fn test_get_config_fork_schedule(self) -> Self {
        let result = self.client.get_config_fork_schedule().await.unwrap().data;

        let expected = vec![self.chain.head_info().unwrap().fork];

        assert_eq!(result, expected);

        self
    }

    pub async fn test_get_config_spec(self) -> Self {
        let result = self.client.get_config_spec().await.unwrap().data;

        let expected = YamlConfig::from_spec::<E>(&self.chain.spec);

        assert_eq!(result, expected);

        self
    }

    pub async fn test_get_config_deposit_contract(self) -> Self {
        let result = self
            .client
            .get_config_deposit_contract()
            .await
            .unwrap()
            .data;

        let expected = DepositContractData {
            address: self.chain.spec.deposit_contract_address,
            chain_id: eth1::DEFAULT_NETWORK_ID.into(),
        };

        assert_eq!(result, expected);

        self
    }

    pub async fn test_get_node_version(self) -> Self {
        let result = self.client.get_node_version().await.unwrap().data;

        let expected = VersionData {
            version: lighthouse_version::version_with_platform(),
        };

        assert_eq!(result, expected);

        self
    }

    pub async fn test_get_node_syncing(self) -> Self {
        let result = self.client.get_node_syncing().await.unwrap().data;
        let head_slot = self.chain.head_info().unwrap().slot;
        let sync_distance = self.chain.slot().unwrap() - head_slot;

        let expected = SyncingData {
            is_syncing: false,
            head_slot,
            sync_distance,
        };

        assert_eq!(result, expected);

        self
    }

    pub async fn test_get_node_identity(self) -> Self {
        let result = self.client.get_node_identity().await.unwrap().data;

        let expected = IdentityData {
            peer_id: self.local_enr.peer_id().to_string(),
            enr: self.local_enr.clone(),
            p2p_addresses: self.local_enr.multiaddr_p2p_tcp(),
            discovery_addresses: self.local_enr.multiaddr_p2p_udp(),
            metadata: eth2::types::MetaData {
                seq_number: 0,
                attnets: "0x0000000000000000".to_string(),
            },
        };

        assert_eq!(result, expected);

        self
    }

    pub async fn test_get_node_health(self) -> Self {
        let status = self.client.get_node_health().await.unwrap();
        assert_eq!(status, StatusCode::OK);

        self
    }

    pub async fn test_get_node_peers_by_id(self) -> Self {
        let result = self
            .client
            .get_node_peers_by_id(self.external_peer_id.clone())
            .await
            .unwrap()
            .data;

        let expected = PeerData {
            peer_id: self.external_peer_id.to_string(),
            enr: None,
            address: EXTERNAL_ADDR.to_string(),
            state: PeerState::Connected,
            direction: PeerDirection::Inbound,
        };

        assert_eq!(result, expected);

        self
    }

    pub async fn test_get_node_peers(self) -> Self {
        let result = self.client.get_node_peers().await.unwrap().data;

        let expected = PeerData {
            peer_id: self.external_peer_id.to_string(),
            enr: None,
            address: EXTERNAL_ADDR.to_string(),
            state: PeerState::Connected,
            direction: PeerDirection::Inbound,
        };

        assert_eq!(result, vec![expected]);

        self
    }

    pub async fn test_get_debug_beacon_states(self) -> Self {
        for state_id in self.interesting_state_ids() {
            let result = self
                .client
                .get_debug_beacon_states(state_id)
                .await
                .unwrap()
                .map(|res| res.data);

            let mut expected = self.get_state(state_id);
            expected.as_mut().map(|state| state.drop_all_caches());

            assert_eq!(result, expected, "{:?}", state_id);
        }

        self
    }

    pub async fn test_get_debug_beacon_heads(self) -> Self {
        let result = self
            .client
            .get_debug_beacon_heads()
            .await
            .unwrap()
            .data
            .into_iter()
            .map(|head| (head.root, head.slot))
            .collect::<Vec<_>>();

        let expected = self.chain.heads();

        assert_eq!(result, expected);

        self
    }

    fn validator_count(&self) -> usize {
        self.chain.head().unwrap().beacon_state.validators.len()
    }

    fn interesting_validator_indices(&self) -> Vec<Vec<u64>> {
        let validator_count = self.validator_count() as u64;

        let mut interesting = vec![
            vec![],
            vec![0],
            vec![0, 1],
            vec![0, 1, 3],
            vec![validator_count],
            vec![validator_count, 1],
            vec![validator_count, 1, 3],
            vec![u64::max_value()],
            vec![u64::max_value(), 1],
            vec![u64::max_value(), 1, 3],
        ];

        interesting.push((0..validator_count).collect());

        interesting
    }

    fn interesting_validator_statuses(&self) -> Vec<Vec<ValidatorStatus>> {
        let interesting = vec![
            vec![],
            vec![ValidatorStatus::Active],
            vec![
                ValidatorStatus::Unknown,
                ValidatorStatus::WaitingForEligibility,
                ValidatorStatus::WaitingForFinality,
                ValidatorStatus::WaitingInQueue,
                ValidatorStatus::StandbyForActive,
                ValidatorStatus::Active,
                ValidatorStatus::ActiveAwaitingVoluntaryExit,
                ValidatorStatus::ActiveAwaitingSlashedExit,
                ValidatorStatus::ExitedVoluntarily,
                ValidatorStatus::ExitedSlashed,
                ValidatorStatus::Withdrawable,
                ValidatorStatus::Withdrawn,
            ],
        ];
        interesting
    }

    pub async fn test_get_validator_duties_attester(self) -> Self {
        let current_epoch = self.chain.epoch().unwrap().as_u64();

        let half = current_epoch / 2;
        let first = current_epoch - half;
        let last = current_epoch + half;

        for epoch in first..=last {
            for indices in self.interesting_validator_indices() {
                let epoch = Epoch::from(epoch);

                // The endpoint does not allow getting duties past the next epoch.
                if epoch > current_epoch + 1 {
                    assert_eq!(
                        self.client
                            .get_validator_duties_attester(epoch, Some(&indices))
                            .await
                            .unwrap_err()
                            .status()
                            .map(Into::into),
                        Some(400)
                    );
                    continue;
                }

                let results = self
                    .client
                    .get_validator_duties_attester(epoch, Some(&indices))
                    .await
                    .unwrap()
                    .data;

                let mut state = self
                    .chain
                    .state_at_slot(
                        epoch.start_slot(E::slots_per_epoch()),
                        StateSkipConfig::WithStateRoots,
                    )
                    .unwrap();
                state
                    .build_committee_cache(RelativeEpoch::Current, &self.chain.spec)
                    .unwrap();

                let expected_len = indices
                    .iter()
                    .filter(|i| **i < state.validators.len() as u64)
                    .count();

                assert_eq!(results.len(), expected_len);

                for (indices_set, &i) in indices.iter().enumerate() {
                    if let Some(duty) = state
                        .get_attestation_duties(i as usize, RelativeEpoch::Current)
                        .unwrap()
                    {
                        let expected = AttesterData {
                            pubkey: state.validators[i as usize].pubkey.clone().into(),
                            validator_index: i,
                            committees_at_slot: duty.committees_at_slot,
                            committee_index: duty.index,
                            committee_length: duty.committee_len as u64,
                            validator_committee_index: duty.committee_position as u64,
                            slot: duty.slot,
                        };

                        let result = results
                            .iter()
                            .find(|duty| duty.validator_index == i)
                            .unwrap();

                        assert_eq!(
                            *result, expected,
                            "epoch: {}, indices_set: {}",
                            epoch, indices_set
                        );
                    } else {
                        assert!(
                            !results.iter().any(|duty| duty.validator_index == i),
                            "validator index should not exist in response"
                        );
                    }
                }
            }
        }

        self
    }

    pub async fn test_get_validator_duties_proposer(self) -> Self {
        let current_epoch = self.chain.epoch().unwrap();

        let result = self
            .client
            .get_validator_duties_proposer(current_epoch)
            .await
            .unwrap()
            .data;

        let mut state = self.chain.head_beacon_state().unwrap();

        while state.current_epoch() < current_epoch {
            per_slot_processing(&mut state, None, &self.chain.spec).unwrap();
        }

        state
            .build_committee_cache(RelativeEpoch::Current, &self.chain.spec)
            .unwrap();

        let expected = current_epoch
            .slot_iter(E::slots_per_epoch())
            .map(|slot| {
                let index = state
                    .get_beacon_proposer_index(slot, &self.chain.spec)
                    .unwrap();
                let pubkey = state.validators[index].pubkey.clone().into();

                ProposerData { pubkey, slot }
            })
            .collect::<Vec<_>>();

        assert_eq!(result, expected);

        self
    }

    pub async fn test_block_production(self) -> Self {
        let fork = self.chain.head_info().unwrap().fork;
        let genesis_validators_root = self.chain.genesis_validators_root;

        for _ in 0..E::slots_per_epoch() * 3 {
            let slot = self.chain.slot().unwrap();
            let epoch = self.chain.epoch().unwrap();

            let proposer_pubkey_bytes = self
                .client
                .get_validator_duties_proposer(epoch)
                .await
                .unwrap()
                .data
                .into_iter()
                .find(|duty| duty.slot == slot)
                .map(|duty| duty.pubkey)
                .unwrap();
            let proposer_pubkey = (&proposer_pubkey_bytes).try_into().unwrap();

            let sk = self
                .validator_keypairs
                .iter()
                .find(|kp| kp.pk == proposer_pubkey)
                .map(|kp| kp.sk.clone())
                .unwrap();

            let randao_reveal = {
                let domain = self.chain.spec.get_domain(
                    epoch,
                    Domain::Randao,
                    &fork,
                    genesis_validators_root,
                );
                let message = epoch.signing_root(domain);
                sk.sign(message).into()
            };

            let block = self
                .client
                .get_validator_blocks::<E>(slot, randao_reveal, None)
                .await
                .unwrap()
                .data;

            let signed_block = block.sign(&sk, &fork, genesis_validators_root, &self.chain.spec);

            self.client.post_beacon_blocks(&signed_block).await.unwrap();

            assert_eq!(self.chain.head_beacon_block().unwrap(), signed_block);

            self.chain.slot_clock.set_slot(slot.as_u64() + 1);
        }

        self
    }

    pub async fn test_get_validator_attestation_data(self) -> Self {
        let mut state = self.chain.head_beacon_state().unwrap();
        let slot = state.slot;
        state
            .build_committee_cache(RelativeEpoch::Current, &self.chain.spec)
            .unwrap();

        for index in 0..state.get_committee_count_at_slot(slot).unwrap() {
            let result = self
                .client
                .get_validator_attestation_data(slot, index)
                .await
                .unwrap()
                .data;

            let expected = self
                .chain
                .produce_unaggregated_attestation(slot, index)
                .unwrap()
                .data;

            assert_eq!(result, expected);
        }

        self
    }

    pub async fn test_get_validator_aggregate_attestation(self) -> Self {
        let attestation = self
            .chain
            .head_beacon_block()
            .unwrap()
            .message
            .body
            .attestations[0]
            .clone();

        let result = self
            .client
            .get_validator_aggregate_attestation(
                attestation.data.slot,
                attestation.data.tree_hash_root(),
            )
            .await
            .unwrap()
            .unwrap()
            .data;

        let expected = attestation;

        assert_eq!(result, expected);

        self
    }

    pub async fn get_aggregate(&mut self) -> SignedAggregateAndProof<E> {
        let slot = self.chain.slot().unwrap();
        let epoch = self.chain.epoch().unwrap();

        let mut head = self.chain.head().unwrap();
        while head.beacon_state.current_epoch() < epoch {
            per_slot_processing(&mut head.beacon_state, None, &self.chain.spec).unwrap();
        }
        head.beacon_state
            .build_committee_cache(RelativeEpoch::Current, &self.chain.spec)
            .unwrap();

        let committee_len = head.beacon_state.get_committee_count_at_slot(slot).unwrap();
        let fork = head.beacon_state.fork;
        let genesis_validators_root = self.chain.genesis_validators_root;

        let mut duties = vec![];
        for i in 0..self.validator_keypairs.len() {
            duties.push(
                self.client
                    .get_validator_duties_attester(epoch, Some(&[i as u64]))
                    .await
                    .unwrap()
                    .data[0]
                    .clone(),
            )
        }

        let (i, kp, duty, proof) = self
            .validator_keypairs
            .iter()
            .enumerate()
            .find_map(|(i, kp)| {
                let duty = duties[i].clone();

                let proof = SelectionProof::new::<E>(
                    duty.slot,
                    &kp.sk,
                    &fork,
                    genesis_validators_root,
                    &self.chain.spec,
                );

                if proof
                    .is_aggregator(committee_len as usize, &self.chain.spec)
                    .unwrap()
                {
                    Some((i, kp, duty, proof))
                } else {
                    None
                }
            })
            .expect("there is at least one aggregator for this epoch")
            .clone();

        if duty.slot > slot {
            self.chain.slot_clock.set_slot(duty.slot.into());
        }

        let attestation_data = self
            .client
            .get_validator_attestation_data(duty.slot, duty.committee_index)
            .await
            .unwrap()
            .data;

        let mut attestation = Attestation {
            aggregation_bits: BitList::with_capacity(duty.committee_length as usize).unwrap(),
            data: attestation_data,
            signature: AggregateSignature::infinity(),
        };

        attestation
            .sign(
                &kp.sk,
                duty.validator_committee_index as usize,
                &fork,
                genesis_validators_root,
                &self.chain.spec,
            )
            .unwrap();

        SignedAggregateAndProof::from_aggregate(
            i as u64,
            attestation,
            Some(proof),
            &kp.sk,
            &fork,
            genesis_validators_root,
            &self.chain.spec,
        )
    }

    pub async fn test_get_validator_aggregate_and_proofs_valid(mut self) -> Self {
        let aggregate = self.get_aggregate().await;

        self.client
            .post_validator_aggregate_and_proof::<E>(&aggregate)
            .await
            .unwrap();

        assert!(self.network_rx.try_recv().is_ok());

        self
    }

    pub async fn test_get_validator_aggregate_and_proofs_invalid(mut self) -> Self {
        let mut aggregate = self.get_aggregate().await;

        aggregate.message.aggregate.data.slot += 1;

        self.client
            .post_validator_aggregate_and_proof::<E>(&aggregate)
            .await
            .unwrap_err();

        assert!(self.network_rx.try_recv().is_err());

        self
    }

    pub async fn test_get_validator_beacon_committee_subscriptions(mut self) -> Self {
        let subscription = BeaconCommitteeSubscription {
            validator_index: 0,
            committee_index: 0,
            committees_at_slot: 1,
            slot: Slot::new(1),
            is_aggregator: true,
        };

        self.client
            .post_validator_beacon_committee_subscriptions(&[subscription])
            .await
            .unwrap();

        self.network_rx.try_recv().unwrap();

        self
    }

    #[cfg(target_os = "linux")]
    pub async fn test_get_lighthouse_health(self) -> Self {
        self.client.get_lighthouse_health().await.unwrap();

        self
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn test_get_lighthouse_health(self) -> Self {
        self.client.get_lighthouse_health().await.unwrap_err();

        self
    }

    pub async fn test_get_lighthouse_syncing(self) -> Self {
        self.client.get_lighthouse_syncing().await.unwrap();

        self
    }

    pub async fn test_get_lighthouse_proto_array(self) -> Self {
        self.client.get_lighthouse_proto_array().await.unwrap();

        self
    }

    pub async fn test_get_lighthouse_validator_inclusion_global(self) -> Self {
        let epoch = self.chain.epoch().unwrap() - 1;
        self.client
            .get_lighthouse_validator_inclusion_global(epoch)
            .await
            .unwrap();

        self
    }

    pub async fn test_get_lighthouse_validator_inclusion(self) -> Self {
        let epoch = self.chain.epoch().unwrap() - 1;
        self.client
            .get_lighthouse_validator_inclusion(epoch, ValidatorId::Index(0))
            .await
            .unwrap();

        self
    }

    pub async fn test_get_lighthouse_eth1_syncing(self) -> Self {
        self.client.get_lighthouse_eth1_syncing().await.unwrap();

        self
    }

    pub async fn test_get_lighthouse_eth1_block_cache(self) -> Self {
        let blocks = self.client.get_lighthouse_eth1_block_cache().await.unwrap();

        assert!(blocks.data.is_empty());

        self
    }

    pub async fn test_get_lighthouse_eth1_deposit_cache(self) -> Self {
        let deposits = self
            .client
            .get_lighthouse_eth1_deposit_cache()
            .await
            .unwrap();

        assert!(deposits.data.is_empty());

        self
    }

    pub async fn test_get_lighthouse_beacon_states_ssz(self) -> Self {
        for state_id in self.interesting_state_ids() {
            let result = self
                .client
                .get_lighthouse_beacon_states_ssz(&state_id)
                .await
                .unwrap();

            let mut expected = self.get_state(state_id);
            expected.as_mut().map(|state| state.drop_all_caches());

            assert_eq!(result, expected, "{:?}", state_id);
        }

        self
    }
}

#[tokio::test(core_threads = 2)]
async fn beacon_get() {
    ApiTester::new()
        .test_beacon_genesis()
        .await
        .test_beacon_states_root()
        .await
        .test_beacon_states_fork()
        .await
        .test_beacon_states_finality_checkpoints()
        .await
        .test_beacon_states_validators()
        .await
        .test_beacon_states_committees()
        .await
        .test_beacon_states_validator_id()
        .await
        .test_beacon_headers_all_slots()
        .await
        .test_beacon_headers_all_parents()
        .await
        .test_beacon_headers_block_id()
        .await
        .test_beacon_blocks()
        .await
        .test_beacon_blocks_attestations()
        .await
        .test_beacon_blocks_root()
        .await
        .test_get_beacon_pool_attestations()
        .await
        .test_get_beacon_pool_attester_slashings()
        .await
        .test_get_beacon_pool_proposer_slashings()
        .await
        .test_get_beacon_pool_voluntary_exits()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn post_beacon_blocks_valid() {
    ApiTester::new().test_post_beacon_blocks_valid().await;
}

#[tokio::test(core_threads = 2)]
async fn post_beacon_blocks_invalid() {
    ApiTester::new().test_post_beacon_blocks_invalid().await;
}

#[tokio::test(core_threads = 2)]
async fn beacon_pools_post_attestations_valid() {
    ApiTester::new()
        .test_post_beacon_pool_attestations_valid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn beacon_pools_post_attestations_invalid() {
    ApiTester::new()
        .test_post_beacon_pool_attestations_invalid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn beacon_pools_post_attester_slashings_valid() {
    ApiTester::new()
        .test_post_beacon_pool_attester_slashings_valid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn beacon_pools_post_attester_slashings_invalid() {
    ApiTester::new()
        .test_post_beacon_pool_attester_slashings_invalid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn beacon_pools_post_proposer_slashings_valid() {
    ApiTester::new()
        .test_post_beacon_pool_proposer_slashings_valid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn beacon_pools_post_proposer_slashings_invalid() {
    ApiTester::new()
        .test_post_beacon_pool_proposer_slashings_invalid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn beacon_pools_post_voluntary_exits_valid() {
    ApiTester::new()
        .test_post_beacon_pool_voluntary_exits_valid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn beacon_pools_post_voluntary_exits_invalid() {
    ApiTester::new()
        .test_post_beacon_pool_voluntary_exits_invalid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn config_get() {
    ApiTester::new()
        .test_get_config_fork_schedule()
        .await
        .test_get_config_spec()
        .await
        .test_get_config_deposit_contract()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn debug_get() {
    ApiTester::new()
        .test_get_debug_beacon_states()
        .await
        .test_get_debug_beacon_heads()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn node_get() {
    ApiTester::new()
        .test_get_node_version()
        .await
        .test_get_node_syncing()
        .await
        .test_get_node_identity()
        .await
        .test_get_node_health()
        .await
        .test_get_node_peers_by_id()
        .await
        .test_get_node_peers()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_duties_attester() {
    ApiTester::new().test_get_validator_duties_attester().await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_duties_attester_with_skip_slots() {
    ApiTester::new()
        .skip_slots(E::slots_per_epoch() * 2)
        .test_get_validator_duties_attester()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_duties_proposer() {
    ApiTester::new().test_get_validator_duties_proposer().await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_duties_proposer_with_skip_slots() {
    ApiTester::new()
        .skip_slots(E::slots_per_epoch() * 2)
        .test_get_validator_duties_proposer()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn block_production() {
    ApiTester::new().test_block_production().await;
}

#[tokio::test(core_threads = 2)]
async fn block_production_with_skip_slots() {
    ApiTester::new()
        .skip_slots(E::slots_per_epoch() * 2)
        .test_block_production()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_attestation_data() {
    ApiTester::new().test_get_validator_attestation_data().await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_attestation_data_with_skip_slots() {
    ApiTester::new()
        .skip_slots(E::slots_per_epoch() * 2)
        .test_get_validator_attestation_data()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_aggregate_attestation() {
    ApiTester::new()
        .test_get_validator_aggregate_attestation()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_aggregate_attestation_with_skip_slots() {
    ApiTester::new()
        .skip_slots(E::slots_per_epoch() * 2)
        .test_get_validator_aggregate_attestation()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_aggregate_and_proofs_valid() {
    ApiTester::new()
        .test_get_validator_aggregate_and_proofs_valid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_aggregate_and_proofs_valid_with_skip_slots() {
    ApiTester::new()
        .skip_slots(E::slots_per_epoch() * 2)
        .test_get_validator_aggregate_and_proofs_valid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_aggregate_and_proofs_invalid() {
    ApiTester::new()
        .test_get_validator_aggregate_and_proofs_invalid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_aggregate_and_proofs_invalid_with_skip_slots() {
    ApiTester::new()
        .skip_slots(E::slots_per_epoch() * 2)
        .test_get_validator_aggregate_and_proofs_invalid()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn get_validator_beacon_committee_subscriptions() {
    ApiTester::new()
        .test_get_validator_beacon_committee_subscriptions()
        .await;
}

#[tokio::test(core_threads = 2)]
async fn lighthouse_endpoints() {
    ApiTester::new()
        .test_get_lighthouse_health()
        .await
        .test_get_lighthouse_syncing()
        .await
        .test_get_lighthouse_proto_array()
        .await
        .test_get_lighthouse_validator_inclusion()
        .await
        .test_get_lighthouse_validator_inclusion_global()
        .await
        .test_get_lighthouse_eth1_syncing()
        .await
        .test_get_lighthouse_eth1_block_cache()
        .await
        .test_get_lighthouse_eth1_deposit_cache()
        .await
        .test_get_lighthouse_beacon_states_ssz()
        .await;
}
