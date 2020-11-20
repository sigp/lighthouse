pub mod api_error;
pub mod api_response;

mod backend;
mod config;
mod handler;
mod rest_api;
mod router;
mod signing_root;
mod upcheck;

use clap::ArgMatches;
use client_backend::Backend;
use config::Config;
use environment::RuntimeContext;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use types::EthSpec;

pub struct Client {
    listening_address: SocketAddr,
}

impl Client {
    pub async fn new<E: EthSpec>(
        context: RuntimeContext<E>,
        cli_args: &ArgMatches<'_>,
    ) -> Result<Self, String> {
        let log = context.executor.log();

        let mut config = Config::default();

        if let Some(address) = cli_args.value_of("listen-address") {
            config.listen_address = address
                .parse::<Ipv4Addr>()
                .map_err(|_| "listen-address is not a valid IPv4 address.")?;
        }

        if let Some(port) = cli_args.value_of("port") {
            config.port = port
                .parse::<u16>()
                .map_err(|_| "port is not a valid u16.")?;
        }

        let backend = Backend::new(cli_args, log)?;

        // It is useful to get the listening address if you have set up your port to be 0.
        let listening_address =
            rest_api::start_server(context.executor, config, backend, context.eth_spec_instance)
                .map_err(|e| format!("Failed to start HTTP API: {:?}", e))?;

        Ok(Self { listening_address })
    }

    pub fn get_listening_address(&self) -> SocketAddr {
        self.listening_address
    }
}
