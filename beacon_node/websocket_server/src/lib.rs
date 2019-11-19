use futures::Future;
use slog::{debug, error, info, warn, Logger};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::thread;
use tokio::runtime::TaskExecutor;
use types::EthSpec;
use ws::{Sender, WebSocket};

mod config;

pub use config::Config;

pub struct WebSocketSender<T: EthSpec> {
    sender: Option<Sender>,
    _phantom: PhantomData<T>,
}

impl<T: EthSpec> WebSocketSender<T> {
    /// Creates a dummy websocket server that never starts and where all future calls are no-ops.
    pub fn dummy() -> Self {
        Self {
            sender: None,
            _phantom: PhantomData,
        }
    }

    pub fn send_string(&self, string: String) -> Result<(), String> {
        if let Some(sender) = &self.sender {
            sender
                .send(string)
                .map_err(|e| format!("Unable to broadcast to websocket clients: {:?}", e))
        } else {
            Ok(())
        }
    }
}

pub fn start_server<T: EthSpec>(
    config: &Config,
    executor: &TaskExecutor,
    log: &Logger,
) -> Result<(WebSocketSender<T>, exit_future::Signal, SocketAddr), String> {
    let server_string = format!("{}:{}", config.listen_address, config.port);

    // Create a server that simply ignores any incoming messages.
    let server = WebSocket::new(|_| |_| Ok(()))
        .map_err(|e| format!("Failed to initialize websocket server: {:?}", e))?
        .bind(server_string.clone())
        .map_err(|e| {
            format!(
                "Failed to bind websocket server to {}: {:?}",
                server_string, e
            )
        })?;

    let actual_listen_addr = server.local_addr().map_err(|e| {
        format!(
            "Failed to read listening addr from websocket server: {:?}",
            e
        )
    })?;

    let broadcaster = server.broadcaster();

    // Produce a signal/channel that can gracefully shutdown the websocket server.
    let exit_signal = {
        let (exit_signal, exit) = exit_future::signal();

        let log_inner = log.clone();
        let broadcaster_inner = server.broadcaster();
        let exit_future = exit.and_then(move |_| {
            if let Err(e) = broadcaster_inner.shutdown() {
                warn!(
                    log_inner,
                    "Websocket server errored on shutdown";
                    "error" => format!("{:?}", e)
                );
            } else {
                info!(log_inner, "Websocket server shutdown");
            }
            Ok(())
        });

        // Place a future on the executor that will shutdown the websocket server when the
        // application exits.
        executor.spawn(exit_future);

        exit_signal
    };

    let log_inner = log.clone();
    let _handle = thread::spawn(move || match server.run() {
        Ok(_) => {
            debug!(
                log_inner,
                "Websocket server thread stopped";
            );
        }
        Err(e) => {
            error!(
                log_inner,
                "Websocket server failed to start";
                "error" => format!("{:?}", e)
            );
        }
    });

    info!(
        log,
        "WebSocket server started";
        "address" => format!("{}", actual_listen_addr.ip()),
        "port" => actual_listen_addr.port(),
    );

    Ok((
        WebSocketSender {
            sender: Some(broadcaster),
            _phantom: PhantomData,
        },
        exit_signal,
        actual_listen_addr,
    ))
}
