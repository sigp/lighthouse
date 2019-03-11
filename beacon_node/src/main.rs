extern crate slog;

mod config;
mod rpc;

use std::path::PathBuf;

use crate::config::LighthouseConfig;
use crate::rpc::start_server;
use beacon_chain::BeaconChain;
use bls::create_proof_of_possession;
use clap::{App, Arg};
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    MemoryDB,
};
use fork_choice::BitwiseLMDGhost;
use slog::{error, info, o, Drain};
use slot_clock::SystemTimeSlotClock;
use ssz::TreeHash;
use std::sync::Arc;
use types::{
    beacon_state::BeaconStateBuilder, BeaconBlock, ChainSpec, Deposit, DepositData, DepositInput,
    Eth1Data, Hash256, Keypair,
};

fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!());

    let matches = App::new("Lighthouse")
        .version("0.0.1")
        .author("Sigma Prime <paul@sigmaprime.io>")
        .about("Eth 2.0 Client")
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .value_name("DIR")
                .help("Data directory for keys and databases.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("Network listen port for p2p connections.")
                .takes_value(true),
        )
        .get_matches();

    let mut config = LighthouseConfig::default();

    // Custom datadir
    if let Some(dir) = matches.value_of("datadir") {
        config.data_dir = PathBuf::from(dir.to_string());
    }

    // Custom p2p listen port
    if let Some(port_str) = matches.value_of("port") {
        if let Ok(port) = port_str.parse::<u16>() {
            config.p2p_listen_port = port;
        } else {
            error!(log, "Invalid port"; "port" => port_str);
            return;
        }
    }

    // Log configuration
    info!(log, "";
          "data_dir" => &config.data_dir.to_str(),
          "port" => &config.p2p_listen_port);

    // Specification (presently fixed to foundation).
    let spec = ChainSpec::foundation();

    // Database (presently in-memory)
    let db = Arc::new(MemoryDB::open());
    let block_store = Arc::new(BeaconBlockStore::new(db.clone()));
    let state_store = Arc::new(BeaconStateStore::new(db.clone()));

    // Slot clock
    let genesis_time = 1_549_935_547; // 12th Feb 2018 (arbitrary value in the past).
    let slot_clock = SystemTimeSlotClock::new(genesis_time, spec.seconds_per_slot)
        .expect("Unable to load SystemTimeSlotClock");
    // Choose the fork choice
    let fork_choice = BitwiseLMDGhost::new(block_store.clone(), state_store.clone());

    /*
     * Generate some random data to start a chain with.
     *
     * This is will need to be replace for production usage.
     */
    let latest_eth1_data = Eth1Data {
        deposit_root: Hash256::zero(),
        block_hash: Hash256::zero(),
    };
    let keypairs: Vec<Keypair> = (0..10)
        .collect::<Vec<usize>>()
        .iter()
        .map(|_| Keypair::random())
        .collect();

    let initial_validator_deposits: Vec<Deposit> = keypairs
        .iter()
        .map(|keypair| Deposit {
            branch: vec![], // branch verification is not specified.
            index: 0,       // index verification is not specified.
            deposit_data: DepositData {
                amount: 32_000_000_000, // 32 ETH (in Gwei)
                timestamp: genesis_time - 1,
                deposit_input: DepositInput {
                    pubkey: keypair.pk.clone(),
                    withdrawal_credentials: Hash256::zero(), // Withdrawal not possible.
                    proof_of_possession: create_proof_of_possession(&keypair, Hash256::zero()),
                },
            },
        })
        .collect();

    let mut state_builder = BeaconStateBuilder::new(genesis_time, latest_eth1_data, &spec);
    state_builder.process_initial_deposits(&initial_validator_deposits, &spec);
    let genesis_state = state_builder.build(&spec).unwrap();
    let state_root = Hash256::from_slice(&genesis_state.hash_tree_root());
    let genesis_block = BeaconBlock::genesis(state_root, &spec);

    // Genesis chain
    let _chain_result = BeaconChain::from_genesis(
        state_store.clone(),
        block_store.clone(),
        slot_clock,
        genesis_state,
        genesis_block,
        spec,
        fork_choice,
    );

    let _server = start_server(log.clone());

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
