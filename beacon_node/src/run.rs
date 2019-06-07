use client::{
    error, notifier, BeaconChainTypes, Client, ClientConfig, InitialiseBeaconChain,
    TestnetDiskBeaconChainTypes, TestnetMemoryBeaconChainTypes,
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

pub fn run_beacon_node(config: ClientConfig, log: &slog::Logger) -> error::Result<()> {
    let runtime = Builder::new()
        .name_prefix("main-")
        .clock(Clock::system())
        .build()
        .map_err(|e| format!("{:?}", e))?;

    let executor = runtime.executor();

    let db_path: PathBuf = config
        .db_path()
        .ok_or_else::<error::Error, _>(|| "Unable to access database path".into())?;
    let db_type = &config.db_type;
    let spec = &config.spec;

    let other_config = config.clone();

    let result = match (db_type.as_str(), spec.as_str()) {
        ("disk", "testnet") => {
            run::<TestnetDiskBeaconChainTypes>(&db_path, config, executor, runtime, log)
        }
        ("memory", "testnet") => {
            run::<TestnetMemoryBeaconChainTypes>(&db_path, config, executor, runtime, log)
        }
        (db_type, spec) => {
            error!(log, "Unknown runtime configuration"; "spec" => spec, "db_type" => db_type);
            Err("Unknown specification and/or db_type.".into())
        }
    };

    if result.is_ok() {
        info!(
            log,
            "Started beacon node";
            "p2p_listen_addresses" => format!("{:?}", &other_config.network.listen_addresses()),
            "data_dir" => format!("{:?}", other_config.data_dir()),
            "spec" => &other_config.spec,
            "db_type" => &other_config.db_type,
        );
    }

    result
}

pub fn run<T>(
    db_path: &Path,
    config: ClientConfig,
    executor: TaskExecutor,
    mut runtime: Runtime,
    log: &slog::Logger,
) -> error::Result<()>
where
    T: BeaconChainTypes + InitialiseBeaconChain<T> + Send + Sync + 'static + Clone,
    T::Store: OpenDatabase,
{
    let store = T::Store::open_database(&db_path)?;

    let client: Client<T> = Client::new(config, store, log.clone(), &executor)?;

    // run service until ctrl-c
    let (ctrlc_send, ctrlc_oneshot) = oneshot::channel();
    let ctrlc_send_c = RefCell::new(Some(ctrlc_send));
    ctrlc::set_handler(move || {
        if let Some(ctrlc_send) = ctrlc_send_c.try_borrow_mut().unwrap().take() {
            ctrlc_send.send(()).expect("Error sending ctrl-c message");
        }
    })
    .map_err(|e| format!("Could not set ctrlc hander: {:?}", e))?;

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
