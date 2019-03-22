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
use slog::{info, o, warn, Drain};
use slot_clock::SystemTimeSlotClock;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use types::{Epoch, Fork};

/// The validator service. This is the main thread that executes and maintains validator
/// duties.
pub struct Service {
    /// The node we currently connected to.
    connected_node_version: String,
    /// The chain id we are processing on.
    chain_id: u16,
    /// The fork state we processing on.
    fork: Fork,
    /// The slot clock keeping track of time.
    slot_clock: Arc<SystemTimeSlotClock>,
    // GRPC Clients
    /// The beacon block GRPC client.
    beacon_block_client: Arc<BeaconBlockServiceClient>,
    /// The validator GRPC client.
    validator_client: Arc<ValidatorServiceClient>,
    /// The attester GRPC client.
    attester_client: Arc<AttestationServiceClient>,
    /// The validator client logger.
    log: slog::Logger,
}

impl Service {
    /// Initialise the service then run the core thread.
    pub fn start(config: ValidatorConfig, log: slog::Logger) {
        // connect to the node and retrieve its properties and initialize the gRPC clients
        let service = Service::initialize_service(&config, log);

        // we have connected to a node and established its parameters. Spin up the core service
        service.run(config);
    }

    ///  Initial connection to the beacon node to determine its properties.
    ///
    ///  This tries to connect to a beacon node. Once connected, it initialised the gRPC clients
    ///  and returns an instance of the service.
    fn initialize_service(config: &ValidatorConfig, log: slog::Logger) -> Self {
        // initialise the beacon node client to check for a connection

        let env = Arc::new(EnvBuilder::new().build());
        // Beacon node gRPC beacon node endpoints.
        let beacon_node_client = {
            let ch = ChannelBuilder::new(env.clone()).connect(&config.server);
            Arc::new(BeaconNodeServiceClient::new(ch))
        };

        // retrieve node information
        let node_info = loop {
            let info = match beacon_node_client.info(&Empty::new()) {
                Err(e) => {
                    warn!(log, "Could not connect to node. Error: {}", e);
                    info!(log, "Retrying in 5 seconds...");
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
                Ok(info) => break info,
            };
        };

        // build requisite objects to form Self
        let genesis_time = node_info.get_genesis_time();

        info!(log,"Beacon node connected"; "Node Version" => node_info.version.clone(), "Chain ID" => node_info.chain_id, "Genesis time" => genesis_time);

        let proto_fork = node_info.get_fork();
        let mut previous_version: [u8; 4] = [0; 4];
        let mut current_version: [u8; 4] = [0; 4];
        previous_version.copy_from_slice(&proto_fork.get_previous_version()[..4]);
        current_version.copy_from_slice(&proto_fork.get_current_version()[..4]);
        let fork = Fork {
            previous_version,
            current_version,
            epoch: Epoch::from(proto_fork.get_epoch()),
        };

        // build the validator slot clock
        let slot_clock = {
            let clock = SystemTimeSlotClock::new(genesis_time, config.spec.seconds_per_slot)
                .expect("Unable to instantiate SystemTimeSlotClock.");
            Arc::new(clock)
        };

        // initialize the RPC clients

        // Beacon node gRPC beacon block endpoints.
        let beacon_block_client = {
            let ch = ChannelBuilder::new(env.clone()).connect(&config.server);
            Arc::new(BeaconBlockServiceClient::new(ch))
        };

        // Beacon node gRPC validator endpoints.
        let validator_client = {
            let ch = ChannelBuilder::new(env.clone()).connect(&config.server);
            Arc::new(ValidatorServiceClient::new(ch))
        };

        //Beacon node gRPC attester endpoints.
        let attester_client = {
            let ch = ChannelBuilder::new(env.clone()).connect(&config.server);
            Arc::new(AttestationServiceClient::new(ch))
        };

        Self {
            connected_node_version: node_info.version,
            chain_id: node_info.chain_id as u16,
            fork,
            slot_clock,
            beacon_block_client,
            validator_client,
            attester_client,
            log,
        }
    }

    fn run(&mut self, config: ValidatorConfig) {
        /*
         * Start threads.
         */
        let mut threads = vec![];
        // TODO: keypairs are randomly generated; they should be loaded from a file or generated.
        // https://github.com/sigp/lighthouse/issues/160
        let keypairs = vec![Keypair::random()];

        let spec = config.spec;

        for keypair in keypairs {
            info!(self.log, "Starting validator services"; "validator" => keypair.pk.concatenated_hex_id());
            let duties_map = Arc::new(EpochDutiesMap::new(spec.slots_per_epoch));
            let epoch_map_for_attester = Arc::new(EpochMap::new(spec.slots_per_epoch));

            // Spawn a new thread to maintain the validator's `EpochDuties`.
            let duties_manager_thread = {
                let spec = spec.clone();
                let duties_map = duties_map.clone();
                let slot_clock = self.slot_clock.clone();
                let log = self.log.clone();
                let beacon_node = self.validator_client.clone();
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
