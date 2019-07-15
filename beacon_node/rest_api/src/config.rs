use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// HTTP REST API Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Enable the REST API server.
    pub enabled: bool,
    /// The IPv4 address the REST API HTTP server will listen on.
    pub listen_address: Ipv4Addr,
    /// The port the REST API HTTP server will listen on.
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: true, // rest_api enabled by default
            listen_address: Ipv4Addr::new(127, 0, 0, 1),
            port: 1248,
        }
    }
}

impl Config {
    pub fn apply_cli_args(&mut self, args: &ArgMatches) -> Result<(), &'static str> {
        if args.is_present("rest-api") {
            self.enabled = true;
        }

        if let Some(rpc_address) = args.value_of("rest-api-address") {
            self.listen_address = rpc_address
                .parse::<Ipv4Addr>()
                .map_err(|_| "rest-api-address is not a valid IPv4 address.")?;
        }

        if let Some(rpc_port) = args.value_of("rpc-port") {
            self.port = rpc_port
                .parse::<u16>()
                .map_err(|_| "rest-api-port is not a valid u16.")?;
        }

        Ok(())
    }
}
