use client::{
    error, notifier, BeaconChainTypes, Client, ClientConfig, ClientType, Eth2Config,
    InitialiseBeaconChain,
};
use futures::sync::oneshot;
use futures::Future;
use slog::{error, info};
use std::cell::RefCell;
use std::path::Path;
use std::path::PathBuf;
use store::{DiskStore, MemoryStore};
use tokio::runtime::Builder;
use tokio::runtime::Runtime;
use tokio::runtime::TaskExecutor;
use tokio_timer::clock::Clock;
use types::{InteropEthSpec, MainnetEthSpec, MinimalEthSpec};

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
        "BeaconNode init";
        "p2p_listen_address" => format!("{:?}", &other_client_config.network.listen_address),
        "data_dir" => format!("{:?}", other_client_config.data_dir()),
        "network_dir" => format!("{:?}", other_client_config.network.network_dir),
        "spec_constants" => &spec_constants,
        "db_type" => &other_client_config.db_type,
    );

    match (db_type.as_str(), spec_constants.as_str()) {
        ("disk", "minimal") => run::<ClientType<DiskStore, MinimalEthSpec>>(
            &db_path,
            client_config,
            eth2_config,
            executor,
            runtime,
            log,
        ),
        ("memory", "minimal") => run::<ClientType<MemoryStore, MinimalEthSpec>>(
            &db_path,
            client_config,
            eth2_config,
            executor,
            runtime,
            log,
        ),
        ("disk", "mainnet") => run::<ClientType<DiskStore, MainnetEthSpec>>(
            &db_path,
            client_config,
            eth2_config,
            executor,
            runtime,
            log,
        ),
        ("memory", "mainnet") => run::<ClientType<MemoryStore, MainnetEthSpec>>(
            &db_path,
            client_config,
            eth2_config,
            executor,
            runtime,
            log,
        ),
        ("disk", "interop") => run::<ClientType<DiskStore, InteropEthSpec>>(
            &db_path,
            client_config,
            eth2_config,
            executor,
            runtime,
            log,
        ),
        ("memory", "interop") => run::<ClientType<MemoryStore, InteropEthSpec>>(
            &db_path,
            client_config,
            eth2_config,
            executor,
            runtime,
            log,
        ),
        (db_type, spec) => {
            error!(log, "Unknown runtime configuration"; "spec_constants" => spec, "db_type" => db_type);
            Err("Unknown specification and/or db_type.".into())
        }
    }
}

/// Performs the type-generic parts of launching a `BeaconChain`.
fn run<T>(
    db_path: &Path,
    client_config: ClientConfig,
    eth2_config: Eth2Config,
    executor: TaskExecutor,
    mut runtime: Runtime,
    log: &slog::Logger,
) -> error::Result<()>
where
    T: BeaconChainTypes + InitialiseBeaconChain<T> + Clone,
    T::Store: OpenDatabase,
{
    let store = T::Store::open_database(&db_path)?;

    let client: Client<T> = Client::new(client_config, eth2_config, store, log.clone(), &executor)?;

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
