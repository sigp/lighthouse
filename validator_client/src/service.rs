/// The validator service. Connects to a beacon node and signs blocks when required.
use crate::attester_service::{AttestationGrpcClient, AttesterService};
use crate::block_producer_service::{BeaconBlockGrpcClient, BlockProducerService};
use crate::config::Config as ValidatorConfig;
use crate::duties::{DutiesManager, DutiesManagerService, EpochDutiesMap};
use attester::test_utils::EpochMap;
use attester::{test_utils::LocalSigner as AttesterLocalSigner, Attester};
use block_proposer::{test_utils::LocalSigner as BlockProposerLocalSigner, BlockProducer};
use bls::Keypair;
use grpcio::{ChannelBuilder, EnvBuilder};
use protos::services::{Empty, NodeInfo};
use protos::services_grpc::{
    AttestationServiceClient, BeaconBlockServiceClient, BeaconNodeServiceClient,
    ValidatorServiceClient,
};
use slog::{info, o, Drain};
use slot_clock::SystemTimeSlotClock;
use std::sync::Arc;
use std::thread;

/// The validator service. This is the main thread that executes and maintains validator
/// duties.
pub struct Service {}

impl Service {
    pub fn start(config: ValidatorConfig, log: slog::Logger) {
        // initialize the RPC clients

        let env = Arc::new(EnvBuilder::new().build());
        // Beacon node gRPC beacon node endpoints.
        let beacon_node_grpc_client = {
            let ch = ChannelBuilder::new(env.clone()).connect(&config.server);
            Arc::new(BeaconNodeServiceClient::new(ch))
        };

        // Beacon node gRPC beacon block endpoints.
        let beacon_block_grpc_client = {
            let ch = ChannelBuilder::new(env.clone()).connect(&config.server);
            Arc::new(BeaconBlockServiceClient::new(ch))
        };

        // Beacon node gRPC validator endpoints.
        let validator_grpc_client = {
            let ch = ChannelBuilder::new(env.clone()).connect(&config.server);
            Arc::new(ValidatorServiceClient::new(ch))
        };

        //Beacon node gRPC attester endpoints.
        let attester_grpc_client = {
            let ch = ChannelBuilder::new(env.clone()).connect(&config.server);
            Arc::new(AttestationServiceClient::new(ch))
        };

        // connect to the node and retrieve its properties
        //        node_info = connect_to_node(beacon_ndoe_grpc_client);

        // retrieve node information
        let node_info = beacon_node_grpc_client.info(&Empty::new());

        info!(log, "Beacon node info: {:?}", node_info);

        // Spec
        let spec = Arc::new(config.spec.clone());

        let genesis_time = 1_549_935_547;
        let slot_clock = {
            info!(log, "Genesis time"; "unix_epoch_seconds" => genesis_time);
            let clock = SystemTimeSlotClock::new(genesis_time, spec.seconds_per_slot)
                .expect("Unable to instantiate SystemTimeSlotClock.");
            Arc::new(clock)
        };

        let poll_interval_millis = spec.seconds_per_slot * 1000 / 10; // 10% epoch time precision.
        info!(log, "Starting block producer service"; "polls_per_epoch" => spec.seconds_per_slot * 1000 / poll_interval_millis);

        /*
         * Start threads.
         */
        let mut threads = vec![];
        // TODO: keypairs are randomly generated; they should be loaded from a file or generated.
        // https://github.com/sigp/lighthouse/issues/160
        let keypairs = vec![Keypair::random()];

        for keypair in keypairs {
            info!(log, "Starting validator services"; "validator" => keypair.pk.concatenated_hex_id());
            let duties_map = Arc::new(EpochDutiesMap::new(spec.slots_per_epoch));
            let epoch_map_for_attester = Arc::new(EpochMap::new(spec.slots_per_epoch));

            // Spawn a new thread to maintain the validator's `EpochDuties`.
            let duties_manager_thread = {
                let spec = spec.clone();
                let duties_map = duties_map.clone();
                let slot_clock = slot_clock.clone();
                let log = log.clone();
                let beacon_node = validator_grpc_client.clone();
                let pubkey = keypair.pk.clone();
                thread::spawn(move || {
                    let manager = DutiesManager {
                        duties_map,
                        pubkey,
                        spec,
                        slot_clock,
                        beacon_node,
                    };
                    let mut duties_manager_service = DutiesManagerService {
                        manager,
                        poll_interval_millis,
                        log,
                    };

                    duties_manager_service.run();
                })
            };

            // Spawn a new thread to perform block production for the validator.
            let producer_thread = {
                let spec = spec.clone();
                let signer = Arc::new(BlockProposerLocalSigner::new(keypair.clone()));
                let duties_map = duties_map.clone();
                let slot_clock = slot_clock.clone();
                let log = log.clone();
                let client = Arc::new(BeaconBlockGrpcClient::new(beacon_block_grpc_client.clone()));
                thread::spawn(move || {
                    let block_producer =
                        BlockProducer::new(spec, duties_map, slot_clock, client, signer);
                    let mut block_producer_service = BlockProducerService {
                        block_producer,
                        poll_interval_millis,
                        log,
                    };

                    block_producer_service.run();
                })
            };

            // Spawn a new thread for attestation for the validator.
            let attester_thread = {
                let signer = Arc::new(AttesterLocalSigner::new(keypair.clone()));
                let epoch_map = epoch_map_for_attester.clone();
                let slot_clock = slot_clock.clone();
                let log = log.clone();
                let client = Arc::new(AttestationGrpcClient::new(attester_grpc_client.clone()));
                thread::spawn(move || {
                    let attester = Attester::new(epoch_map, slot_clock, client, signer);
                    let mut attester_service = AttesterService {
                        attester,
                        poll_interval_millis,
                        log,
                    };

                    attester_service.run();
                })
            };

            threads.push((duties_manager_thread, producer_thread, attester_thread));
        }

        // Naively wait for all the threads to complete.
        for tuple in threads {
            let (manager, producer, attester) = tuple;
            let _ = producer.join();
            let _ = manager.join();
            let _ = attester.join();
        }
    }
}
