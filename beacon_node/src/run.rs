use crate::config::Config;
use crate::error;
use crate::rpc::start_server;
use beacon_chain::BeaconChain;
use bls::create_proof_of_possession;
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    ClientDB, DBType, DiskDB, MemoryDB,
};
use fork_choice::{BitwiseLMDGhost, ForkChoiceAlgorithm};
use futures::sync::oneshot;
use network::NetworkConfiguration;
use slog::{error, info};
use slot_clock::SystemTimeSlotClock;
use std::cell::RefCell;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime, TaskExecutor};
use types::{ChainSpec, Deposit, DepositData, DepositInput, Eth1Data, Hash256, Keypair};

pub fn run_beacon_node(config: Config, log: &slog::Logger) -> error::Result<()> {
    let mut runtime = Builder::new()
        .name_prefix("main-")
        .build()
        .map_err(|e| format!("{:?}", e))?;

    // Log configuration
    info!(log, "";
          "data_dir" => &config.data_dir.to_str(),
          "port" => &config.net_conf.listen_port);

    // run service until ctrl-c
    let (ctrlc_send, ctrlc) = oneshot::channel();
    let ctrlc_send_c = RefCell::new(Some(ctrlc_send));
    ctrlc::set_handler(move || {
        if let Some(ctrlc_send) = ctrlc_send_c.try_borrow_mut().unwrap().take() {
            ctrlc_send
                .send(())
                .expect("Error sending termination message");
        }
    });

    let executor = runtime.executor();

    start(config, log, executor);

    runtime.block_on(ctrlc);

    info!(log, "Shutting down.");
    //TODO: handle shutdown of processes gracefully

    Ok(())
}

fn start(config: Config, log: &slog::Logger, executor: TaskExecutor) {}
