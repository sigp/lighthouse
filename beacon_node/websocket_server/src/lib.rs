use serde_derive::{Deserialize, Serialize};
use slog::{error, info, Logger};
use std::net::Ipv4Addr;
use std::thread;
use types::EthSpec;
use ws::{Sender, WebSocket};

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    /// The IPv4 address the REST API HTTP server will listen on.
    pub listen_address: Ipv4Addr,
    /// The port the REST API HTTP server will listen on.
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: true,
            listen_address: Ipv4Addr::new(127, 0, 0, 1),
            port: 5053,
        }
    }
}

pub struct WebSocketSender {
    sender: Sender,
}

impl WebSocketSender {
    pub fn send_string(&self, string: String) -> Result<(), String> {
        self.sender
            .send(string)
            .map_err(|e| format!("Unable to broadcast to websocket clients: {:?}", e))
    }
}

pub fn start_server<T: EthSpec>(config: &Config, log: &Logger) -> Result<WebSocketSender, String> {
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

    let log_inner = log.clone();
    let _handle = thread::spawn(move || match server.listen(server_string) {
        Ok(_) => {
            info!(
                log_inner,
                "Websocket server stopped";
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

    Ok(WebSocketSender {
        sender: broadcaster,
    })
}
