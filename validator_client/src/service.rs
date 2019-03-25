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
use protos::services::Empty;
use protos::services_grpc::{
    AttestationServiceClient, BeaconBlockServiceClient, BeaconNodeServiceClient,
    ValidatorServiceClient,
};
use slog::{debug, info, warn};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::ops::Sub;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::prelude::*;
use tokio::runtime::Builder;
use tokio::timer::Interval;
use tokio_timer::clock::Clock;
use types::{Epoch, Fork, Slot};

//TODO: This service should be simplified in the future. Can be made more steamlined.

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
    /// The current slot we are processing.
    current_slot: Slot,
    /// Duration until the next slot. This is used for initializing the tokio timer interval.
    duration_to_next_slot: Duration,
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
                Ok(info) => {
                    if SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        > Duration::from_secs(info.genesis_time)
                    {
                        warn!(
                            log,
                            "Beacon Node's genesis time is in the future. No work to do.\n Exiting"
                        );
                        //                        return Err("Genesis Time in the future");
                    }
                    break info;
                }
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

        //TODO: Add error chain. Handle errors
        let current_slot = slot_clock.present_slot().unwrap().unwrap().sub(1);

        // calculate the duration to the next slot
        let duration_to_next_slot = {
            let syslot_time = SystemTime::now();
            let duration_since_epoch = syslot_time.duration_since(SystemTime::UNIX_EPOCH).unwrap();
            let mut duration_to_next_slot = None;
            if let Some(duration_since_genesis) =
                duration_since_epoch.checked_sub(Duration::from_secs(genesis_time))
            {
                let elapsed_slots = duration_since_epoch
                    .as_secs()
                    .checked_div(config.spec.seconds_per_slot as u64)
                    .unwrap();
                duration_to_next_slot = Some(
                    Duration::from_secs(
                        (elapsed_slots + 1)
                            .checked_mul(config.spec.seconds_per_slot)
                            .unwrap(),
                    )
                    .checked_sub(duration_since_genesis)
                    .expect("This should never saturate"),
                );
            }
            duration_to_next_slot.unwrap_or_else(|| Duration::from_secs(0))
        };

        Self {
            connected_node_version: node_info.version,
            chain_id: node_info.chain_id as u16,
            fork,
            slot_clock,
            current_slot,
            duration_to_next_slot,
            beacon_block_client,
            validator_client,
            attester_client,
            log,
        }
    }

    /// Initialise the service then run the core thread.
    pub fn start(config: ValidatorConfig, log: slog::Logger) {
        // connect to the node and retrieve its properties and initialize the gRPC clients
        let service = Service::initialize_service(&config, log);

        // we have connected to a node and established its parameters. Spin up the core service

        // set up the validator service runtime
        let mut runtime = Builder::new()
            .clock(Clock::system())
            .name_prefix("validator-client-")
            .build()
            .unwrap();

        // set up the validator work interval - start at next slot and proceed every slot
        // TODO: Error chain handle errors.
        let interval = {
            // Set the interval to start at the next slot, and every slot after
            let slot_duration = Duration::from_secs(config.spec.seconds_per_slot);
            //TODO: Handle checked add correctly
            Interval::new(
                Instant::now() + service.duration_to_next_slot,
                slot_duration,
            )
        };

        // kick off core service

        // generate keypairs

        // TODO: keypairs are randomly generated; they should be loaded from a file or generated.
        // https://github.com/sigp/lighthouse/issues/160
        let keypairs = Arc::new(vec![Keypair::random()]);

        // build requisite objects to pass to core thread.
        let duties_map = Arc::new(EpochDutiesMap::new(config.spec.slots_per_epoch));
        let epoch_map_for_attester = Arc::new(EpochMap::new(config.spec.slots_per_epoch));
        let manager = DutiesManager {
            duties_map,
            pubkeys: keypairs.iter().map(|keypair| keypair.pk.clone()).collect(),
            spec: Arc::new(config.spec),
            slot_clock: service.slot_clock.clone(),
            beacon_node: service.validator_client.clone(),
        };

        runtime.block_on(interval.for_each(move |_| {
            // update duties
            debug!(
                service.log,
                "Processing slot: {}",
                service.slot_clock.present_slot().unwrap().unwrap().as_u64()
            );
            manager.poll();
            Ok(())
        }));
    }

    /*

    let duties_map = Arc::new(EpochDutiesMap::new(spec.slots_per_epoch));
    let epoch_map_for_attester = Arc::new(EpochMap::new(spec.slots_per_epoch));


    for keypair in keypairs {
        info!(self.log, "Starting validator services"; "validator" => keypair.pk.concatenated_hex_id());

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
    */
}
