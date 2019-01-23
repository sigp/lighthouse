use self::block_producer_service::{BeaconBlockGrpcClient, BlockProducerService};
use self::duties::{DutiesManager, DutiesManagerService, EpochDutiesMap};
use crate::config::ClientConfig;
use block_producer::BlockProducer;
use bls::Keypair;
use clap::{App, Arg};
use grpcio::{ChannelBuilder, EnvBuilder};
use protos::services_grpc::{BeaconBlockServiceClient, ValidatorServiceClient};
use slog::{error, info, o, Drain};
use slot_clock::SystemTimeSlotClock;
use spec::ChainSpec;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::thread;

mod block_producer_service;
mod config;
mod duties;

fn main() {
    // Logging
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!());

    // CLI
    let matches = App::new("Lighthouse Validator Client")
        .version("0.0.1")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Validator Client")
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .value_name("DIR")
                .help("Data directory for keys and databases.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("server")
                .long("server")
                .value_name("server")
                .help("Address to connect to BeaconNode.")
                .takes_value(true),
        )
        .get_matches();

    let mut config = ClientConfig::default();

    // Custom datadir
    if let Some(dir) = matches.value_of("datadir") {
        config.data_dir = PathBuf::from(dir.to_string());
    }

    // Custom server port
    if let Some(server_str) = matches.value_of("server") {
        if let Ok(addr) = server_str.parse::<u16>() {
            config.server = addr.to_string();
        } else {
            error!(log, "Invalid address"; "server" => server_str);
            return;
        }
    }

    // Log configuration
    info!(log, "";
          "data_dir" => &config.data_dir.to_str(),
          "server" => &config.server);

    // Beacon node gRPC beacon block endpoints.
    let beacon_block_grpc_client = {
        let env = Arc::new(EnvBuilder::new().build());
        let ch = ChannelBuilder::new(env).connect(&config.server);
        Arc::new(BeaconBlockServiceClient::new(ch))
    };

    // Beacon node gRPC validator endpoints.
    let validator_grpc_client = {
        let env = Arc::new(EnvBuilder::new().build());
        let ch = ChannelBuilder::new(env).connect(&config.server);
        Arc::new(ValidatorServiceClient::new(ch))
    };

    // Ethereum
    //
    // TODO: Permit loading a custom spec from file.
    // https://github.com/sigp/lighthouse/issues/160
    let spec = Arc::new(ChainSpec::foundation());

    // Clock for determining the present slot.
    let slot_clock = {
        info!(log, "Genesis time"; "unix_epoch_seconds" => spec.genesis_time);
        let clock = SystemTimeSlotClock::new(spec.genesis_time, spec.slot_duration)
            .expect("Unable to instantiate SystemTimeSlotClock.");
        Arc::new(RwLock::new(clock))
    };

    let poll_interval_millis = spec.slot_duration * 1000 / 10; // 10% epoch time precision.
    info!(log, "Starting block producer service"; "polls_per_epoch" => spec.slot_duration * 1000 / poll_interval_millis);

    /*
     * Start threads.
     */
    let mut threads = vec![];
    // TODO: keypairs are randomly generated; they should be loaded from a file or generated.
    // https://github.com/sigp/lighthouse/issues/160
    let keypairs = vec![Keypair::random()];

    for keypair in keypairs {
        info!(log, "Starting validator services"; "validator" => keypair.pk.concatenated_hex_id());
        let duties_map = Arc::new(EpochDutiesMap::new());

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
            let duties_map = duties_map.clone();
            let slot_clock = slot_clock.clone();
            let log = log.clone();
            let client = Arc::new(BeaconBlockGrpcClient::new(beacon_block_grpc_client.clone()));
            thread::spawn(move || {
                let block_producer = BlockProducer::new(spec, duties_map, slot_clock, client);
                let mut block_producer_service = BlockProducerService {
                    block_producer,
                    poll_interval_millis,
                    log,
                };

                block_producer_service.run();
            })
        };

        threads.push((duties_manager_thread, producer_thread));
    }

    // Naively wait for all the threads to complete.
    for tuple in threads {
        let (manager, producer) = tuple;
        let _ = producer.join();
        let _ = manager.join();
    }
}
