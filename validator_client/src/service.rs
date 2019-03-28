/// The validator service. Connects to a beacon node and signs blocks when required.
use crate::attester_service::{AttestationGrpcClient, AttesterService};
use crate::block_producer_service::{BeaconBlockGrpcClient, BlockProducerService};
use crate::config::Config as ValidatorConfig;
use crate::duties::UpdateOutcome;
use crate::duties::{DutiesManager, EpochDutiesMap};
use crate::error as error_chain;
use crate::error::ErrorKind;
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
use slog::{debug, error, info, warn};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::sync::Arc;
use std::sync::RwLock;
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
    /// The slot clock for this service.
    slot_clock: SystemTimeSlotClock,
    /// The current slot we are processing.
    current_slot: Slot,
    /// The number of slots per epoch to allow for converting slots to epochs.
    slots_per_epoch: u64,
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
    fn initialize_service(
        config: &ValidatorConfig,
        log: slog::Logger,
    ) -> error_chain::Result<Self> {
        // initialise the beacon node client to check for a connection

        let env = Arc::new(EnvBuilder::new().build());
        // Beacon node gRPC beacon node endpoints.
        let beacon_node_client = {
            let ch = ChannelBuilder::new(env.clone()).connect(&config.server);
            Arc::new(BeaconNodeServiceClient::new(ch))
        };

        // retrieve node information
        let node_info = loop {
            match beacon_node_client.info(&Empty::new()) {
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
                        .as_secs()
                        < info.genesis_time
                    {
                        warn!(
                            log,
                            "Beacon Node's genesis time is in the future. No work to do.\n Exiting"
                        );
                        return Err("Genesis time in the future".into());
                    }
                    break info;
                }
            };
        };

        // build requisite objects to form Self
        let genesis_time = node_info.get_genesis_time();
        let genesis_slot = Slot::from(node_info.get_genesis_slot());

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

        // build the validator slot clock
        let slot_clock =
            SystemTimeSlotClock::new(genesis_slot, genesis_time, config.spec.seconds_per_slot)
                .expect("Unable to instantiate SystemTimeSlotClock.");

        let current_slot = slot_clock
            .present_slot()
            .map_err(|e| ErrorKind::SlotClockError(e))?
            .expect("Genesis must be in the future");

        Ok(Self {
            connected_node_version: node_info.version,
            chain_id: node_info.chain_id as u16,
            fork,
            slot_clock,
            current_slot,
            slots_per_epoch: config.spec.slots_per_epoch,
            beacon_block_client,
            validator_client,
            attester_client,
            log,
        })
    }

    /// Initialise the service then run the core thread.
    pub fn start(config: ValidatorConfig, log: slog::Logger) -> error_chain::Result<()> {
        // connect to the node and retrieve its properties and initialize the gRPC clients
        let service = Service::initialize_service(&config, log)?;

        // we have connected to a node and established its parameters. Spin up the core service

        // set up the validator service runtime
        let mut runtime = Builder::new()
            .clock(Clock::system())
            .name_prefix("validator-client-")
            .build()
            .map_err(|e| format!("Tokio runtime failed: {}", e))?;

        let duration_to_next_slot = service
            .slot_clock
            .duration_to_next_slot()
            .map_err(|e| format!("System clock error: {:?}", e))?
            .expect("Cannot start before genesis");

        // set up the validator work interval - start at next slot and proceed every slot
        let interval = {
            // Set the interval to start at the next slot, and every slot after
            let slot_duration = Duration::from_secs(config.spec.seconds_per_slot);
            //TODO: Handle checked add correctly
            Interval::new(Instant::now() + duration_to_next_slot, slot_duration)
        };

        /* kick off core service */

        // generate keypairs

        // TODO: keypairs are randomly generated; they should be loaded from a file or generated.
        // https://github.com/sigp/lighthouse/issues/160
        let keypairs: Arc<Vec<Keypair>> =
            Arc::new((0..10).into_iter().map(|_| Keypair::random()).collect());
        /* build requisite objects to pass to core thread */

        // Builds a mapping of Epoch -> Map(PublicKey, EpochDuty)
        // where EpochDuty contains slot numbers and attestation data that each validator needs to
        // produce work on.
        let duties_map = RwLock::new(EpochDutiesMap::new(config.spec.slots_per_epoch));

        // builds a manager which maintains the list of current duties for all known validators
        // and can check when a validator needs to perform a task.
        let manager = Arc::new(DutiesManager {
            duties_map,
            pubkeys: keypairs.iter().map(|keypair| keypair.pk.clone()).collect(),
            beacon_node: service.validator_client.clone(),
        });

        // run the core thread
        runtime.block_on(
            interval
                .for_each(move |_| {
                    let log = service.log.clone();

                    /* get the current slot and epoch */
                    let current_slot = match service.slot_clock.present_slot() {
                        Err(e) => {
                            error!(log, "SystemTimeError {:?}", e);
                            return Ok(());
                        }
                        Ok(slot) => slot.expect("Genesis is in the future"),
                    };

                    let current_epoch = current_slot.epoch(service.slots_per_epoch);

                    debug_assert!(
                        current_slot > service.current_slot,
                        "The Timer should poll a new slot"
                    );

                    info!(log, "Processing slot: {}", current_slot.as_u64());

                    /* check for new duties */

                    let cloned_manager = manager.clone();
                    let cloned_log = log.clone();
                    // spawn a new thread separate to the runtime
                    std::thread::spawn(move || {
                        cloned_manager.run_update(current_epoch.clone(), cloned_log.clone());
                        dbg!("Finished thread");
                    });

                    /* execute any specified duties */

                    if let Some(work) = manager.get_current_work(current_slot) {
                        for (_public_key, work_type) in work {
                            if work_type.produce_block {
                                // TODO: Produce a beacon block in a new thread
                            }
                            if work_type.attestation_duty.is_some() {
                                // available AttestationDuty info
                                let attestation_duty =
                                    work_type.attestation_duty.expect("Cannot be None");
                                //TODO: Produce an attestation in a new thread
                            }
                        }
                    }

                    Ok(())
                })
                .map_err(|e| format!("Service thread failed: {:?}", e)),
        );

        // completed a slot process
        Ok(())
    }

    /*

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
