use clap::ArgMatches;
use serde_derive::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// RPC Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Enable the RPC server.
    pub enabled: bool,
    /// The IPv4 address the RPC will listen on.
    pub listen_address: Ipv4Addr,
    /// The port the RPC will listen on.
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: true,
            listen_address: Ipv4Addr::new(127, 0, 0, 1),
            port: 5051,
        }
    }
}

impl Config {
    pub fn apply_cli_args(&mut self, args: &ArgMatches) -> Result<(), &'static str> {
        if args.is_present("no-grpc") {
            self.enabled = false;
        }

        if let Some(rpc_address) = args.value_of("rpc-address") {
            self.listen_address = rpc_address
                .parse::<Ipv4Addr>()
                .map_err(|_| "rpc-address is not IPv4 address")?;
        }

        if let Some(rpc_port) = args.value_of("rpc-port") {
            self.port = rpc_port.parse::<u16>().map_err(|_| "rpc-port is not u16")?;
        }

        Ok(())
    }
}
