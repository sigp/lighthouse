use client::{error, notifier, Client, ClientConfig, Eth1BackendMethod, Eth2Config};
use futures::sync::oneshot;
use futures::Future;
use slog::{error, info};
use std::cell::RefCell;
use std::path::Path;
use std::path::PathBuf;
use store::Store;
use store::{DiskStore, MemoryStore};
use tokio::runtime::Builder;
use tokio::runtime::Runtime;
use tokio::runtime::TaskExecutor;
use tokio_timer::clock::Clock;
use types::{EthSpec, InteropEthSpec, MainnetEthSpec, MinimalEthSpec};

/// Reads the configuration and initializes a `BeaconChain` with the required types and parameters.
///
/// Spawns an executor which performs syncing, networking, block production, etc.
///
/// Blocks the current thread, returning after the `BeaconChain` has exited or a `Ctrl+C`
/// signal.
pub fn run_beacon_node(
    client_config: ClientConfig,
    eth2_config: Eth2Config,
    log: &slog::Logger,
) -> error::Result<()> {
    let runtime = Builder::new()
        .name_prefix("main-")
        .clock(Clock::system())
        .build()
        .map_err(|e| format!("{:?}", e))?;

    let executor = runtime.executor();

    let db_path: PathBuf = client_config
        .db_path()
        .ok_or_else::<error::Error, _>(|| "Unable to access database path".into())?;
    let db_type = &client_config.db_type;
    let spec_constants = eth2_config.spec_constants.clone();

    let other_client_config = client_config.clone();

    info!(
        log,
        "Starting beacon node";
        "p2p_listen_address" => format!("{}", &other_client_config.network.listen_address),
        "db_type" => &other_client_config.db_type,
        "spec_constants" => &spec_constants,
    );

    macro_rules! run_client {
        ($store: ty, $eth_spec: ty) => {
            run::<$store, $eth_spec>(&db_path, client_config, eth2_config, executor, runtime, log)
        };
    }

    if let Eth1BackendMethod::Web3 { .. } = client_config.eth1_backend_method {
        return Err("Starting from web3 backend is not supported for interop.".into());
    }

    match (db_type.as_str(), spec_constants.as_str()) {
        ("disk", "minimal") => run_client!(DiskStore, MinimalEthSpec),
        ("disk", "mainnet") => run_client!(DiskStore, MainnetEthSpec),
        ("disk", "interop") => run_client!(DiskStore, InteropEthSpec),
        ("memory", "minimal") => run_client!(MemoryStore, MinimalEthSpec),
        ("memory", "mainnet") => run_client!(MemoryStore, MainnetEthSpec),
        ("memory", "interop") => run_client!(MemoryStore, InteropEthSpec),
        (db_type, spec) => {
            error!(log, "Unknown runtime configuration"; "spec_constants" => spec, "db_type" => db_type);
            Err("Unknown specification and/or db_type.".into())
        }
    }
}

/// Performs the type-generic parts of launching a `BeaconChain`.
fn run<S, E>(
    db_path: &Path,
    client_config: ClientConfig,
    eth2_config: Eth2Config,
    executor: TaskExecutor,
    mut runtime: Runtime,
    log: &slog::Logger,
) -> error::Result<()>
where
    S: Store + Clone + 'static + OpenDatabase,
    E: EthSpec,
{
    let store = S::open_database(&db_path)?;

    let client: Client<S, E> =
        Client::new(client_config, eth2_config, store, log.clone(), &executor)?;

    // run service until ctrl-c
    let (ctrlc_send, ctrlc_oneshot) = oneshot::channel();
    let ctrlc_send_c = RefCell::new(Some(ctrlc_send));
    ctrlc::set_handler(move || {
        if let Some(ctrlc_send) = ctrlc_send_c.try_borrow_mut().unwrap().take() {
            ctrlc_send.send(()).expect("Error sending ctrl-c message");
        }
    })
    .map_err(|e| format!("Could not set ctrlc handler: {:?}", e))?;

    let (exit_signal, exit) = exit_future::signal();

    notifier::run(&client, executor, exit);

    runtime
        .block_on(ctrlc_oneshot)
        .map_err(|e| format!("Ctrlc oneshot failed: {:?}", e))?;

    // perform global shutdown operations.
    info!(log, "Shutting down..");
    exit_signal.fire();
    // shutdown the client
    //    client.exit_signal.fire();
    drop(client);
    runtime.shutdown_on_idle().wait().unwrap();
    Ok(())
}

/// A convenience trait, providing a method to open a database.
///
/// Panics if unable to open the database.
pub trait OpenDatabase: Sized {
    fn open_database(path: &Path) -> error::Result<Self>;
}

impl OpenDatabase for MemoryStore {
    fn open_database(_path: &Path) -> error::Result<Self> {
        Ok(MemoryStore::open())
    }
}

impl OpenDatabase for DiskStore {
    fn open_database(path: &Path) -> error::Result<Self> {
        DiskStore::open(path).map_err(|e| format!("Unable to open database: {:?}", e).into())
    }
}
