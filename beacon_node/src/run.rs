use client::client_types::{DiskDBTestingClientType, MemoryDBTestingClientType};
use client::error;
use client::{notifier, Client, ClientConfig, ClientTypes};
use db::DBType;
use futures::sync::oneshot;
use futures::Future;
use slog::info;
use std::cell::RefCell;
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

    // Log configuration
    info!(log, "Listening on {:?}", &config.net_conf.listen_addresses;
          "data_dir" => &config.data_dir.to_str(),
          "port" => &config.net_conf.listen_port);

    let executor = runtime.executor();

    match config.db_type {
        DBType::RocksDB => {
            let client: Client<DiskDBTestingClientType> =
                Client::new(config, log.clone(), &executor)?;

            run(client, executor, runtime, log)
        }
        DBType::Memory => {
            let client: Client<MemoryDBTestingClientType> =
                Client::new(config, log.clone(), &executor)?;

            run(client, executor, runtime, log)
        }
    }
}

pub fn run<T: ClientTypes>(
    client: Client<T>,
    executor: TaskExecutor,
    mut runtime: Runtime,
    log: &slog::Logger,
) -> error::Result<()> {
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
