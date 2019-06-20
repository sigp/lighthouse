use clap::ArgMatches;
use eth2_libp2p::multiaddr::Protocol;
use eth2_libp2p::Multiaddr;
use fork_choice::ForkChoiceAlgorithm;
use http_server::HttpServerConfig;
use network::NetworkConfig;
use network::{ChainType, NetworkConfig};
use serde_derive::{Deserialize, Serialize};
use slog::{error, o, Drain, Level};
use std::fs;
use std::path::PathBuf;

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub data_dir: PathBuf,
    pub db_type: String,
    db_name: String,
    pub network: network::NetworkConfig,
    pub rpc: rpc::RPCConfig,
    pub http: HttpServerConfig,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(".lighthouse"),
            db_type: "disk".to_string(),
            db_name: "chain_db".to_string(),
            // Note: there are no default bootnodes specified.
            // Once bootnodes are established, add them here.
            network: NetworkConfig::new(vec![]),
            rpc: rpc::RPCConfig::default(),
            http: HttpServerConfig::default(),
        }
    }
}

impl ClientConfig {
    /// Returns the path to which the client may initialize an on-disk database.
    pub fn db_path(&self) -> Option<PathBuf> {
        self.data_dir()
            .and_then(|path| Some(path.join(&self.db_name)))
    }

    /// Returns the core path for the client.
    pub fn data_dir(&self) -> Option<PathBuf> {
        let path = dirs::home_dir()?.join(&self.data_dir);
        fs::create_dir_all(&path).ok()?;
        Some(path)
    }

    /// Apply the following arguments to `self`, replacing values if they are specified in `args`.
    ///
    /// Returns an error if arguments are obviously invalid. May succeed even if some values are
    /// invalid.
    pub fn apply_cli_args(&mut self, args: &ArgMatches) -> Result<(), &'static str> {
        if let Some(dir) = args.value_of("datadir") {
            self.data_dir = PathBuf::from(dir);
        };

        if let Some(dir) = args.value_of("db") {
            self.db_type = dir.to_string();
        }

        self.network.apply_cli_args(args)?;
        self.rpc.apply_cli_args(args)?;
        self.http.apply_cli_args(args)?;

        Ok(())
    }
}
