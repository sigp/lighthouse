use client::{error, ClientBuilder, ClientConfig, Eth1BackendMethod, Eth2Config};
use futures::sync::oneshot;
use futures::Future;
use slog::{error, info};
use std::cell::RefCell;
use std::path::Path;
use std::path::PathBuf;
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
    log: slog::Logger,
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
    let spec_constants = eth2_config.spec_constants.clone();

    let other_client_config = client_config.clone();

    info!(
        log,
        "Starting beacon node";
        "p2p_listen_address" => format!("{}", &other_client_config.network.listen_address),
        "db_type" => &other_client_config.db_type,
        "spec_constants" => &spec_constants,
    );

    if let Eth1BackendMethod::Web3 { .. } = client_config.eth1_backend_method {
        return Err("Starting from web3 backend is not supported for interop.".into());
    }

    macro_rules! run_client {
        ($eth_spec: ident) => {
            run(
                $eth_spec,
                &db_path,
                client_config,
                eth2_config,
                executor,
                runtime,
                log,
            )
        };
    }

    match spec_constants.as_str() {
        "minimal" => run_client!(MinimalEthSpec),
        "mainnet" => run_client!(MainnetEthSpec),
        "interop" => run_client!(InteropEthSpec),
        spec => {
            error!(log, "Unknown runtime configuration"; "spec_constants" => spec);
            Err("Unknown specification.".into())
        }
    }
}

/// Performs the type-generic parts of launching a `BeaconChain`.
fn run<E: EthSpec>(
    eth_spec_instance: E,
    db_path: &Path,
    client_config: ClientConfig,
    eth2_config: Eth2Config,
    executor: TaskExecutor,
    mut runtime: Runtime,
    log: slog::Logger,
) -> error::Result<()>
where
    E: EthSpec,
{
    let client = ClientBuilder::new(eth_spec_instance)
        .logger(log.clone())
        .disk_store(db_path)?
        .executor(executor)
        .beacon_checkpoint(&client_config.beacon_chain_start_method)?
        .system_time_slot_clock()?
        .dummy_eth1_backend()
        .websocket_event_handler(client_config.websocket_server.clone())?
        .beacon_chain()?
        .libp2p_network(&client_config.network)?
        .http_server(&client_config, &eth2_config)?
        .grpc_server(&client_config.rpc)?
        .peer_count_notifier()?
        .slot_notifier()?
        .build();

    // run service until ctrl-c
    let (ctrlc_send, ctrlc_oneshot) = oneshot::channel();
    let ctrlc_send_c = RefCell::new(Some(ctrlc_send));
    ctrlc::set_handler(move || {
        if let Some(ctrlc_send) = ctrlc_send_c.try_borrow_mut().unwrap().take() {
            ctrlc_send.send(()).expect("Error sending ctrl-c message");
        }
    })
    .map_err(|e| format!("Could not set ctrlc handler: {:?}", e))?;

    runtime
        .block_on(ctrlc_oneshot)
        .map_err(|e| format!("Ctrlc oneshot failed: {:?}", e))?;

    info!(log, "Shutting down..");

    drop(client);

    runtime.shutdown_on_idle().wait().unwrap();

    Ok(())
}
