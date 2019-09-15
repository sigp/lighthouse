use beacon_chain::events::{EventHandler, EventKind};
use futures::Future;
use slog::{debug, error, info, warn, Logger};
use std::marker::PhantomData;
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

impl<T: EthSpec> EventHandler<T> for WebSocketSender<T> {
    fn register(&self, kind: EventKind<T>) -> Result<(), String> {
        self.send_string(
            serde_json::to_string(&kind)
                .map_err(|e| format!("Unable to serialize event: {:?}", e))?,
        )
    }
}

pub fn start_server<T: EthSpec>(
    config: &Config,
    executor: &TaskExecutor,
    log: &Logger,
) -> Result<(WebSocketSender<T>, exit_future::Signal), String> {
    let server_string = format!("{}:{}", config.listen_address, config.port);

    info!(
        log,
        "Websocket server starting";
        "listen_address" => &server_string
    );

    // Create a server that simply ignores any incoming messages.
    let server = WebSocket::new(|_| |_| Ok(()))
        .map_err(|e| format!("Failed to initialize websocket server: {:?}", e))?;

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
    let _handle = thread::spawn(move || match server.listen(server_string) {
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

    Ok((
        WebSocketSender {
            sender: Some(broadcaster),
            _phantom: PhantomData,
        },
        exit_signal,
    ))
}
