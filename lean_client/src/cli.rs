pub use clap::{FromArgMatches, Parser};
use clap_utils::FLAG_HEADER;
use clap_utils::get_color_style;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    name = "lean_validator_node",
    visible_aliases = &["l", "ln", "lean-node"],
    about = "lean node follows the lean consensus for ethereum chain",
    styles = get_color_style(),
    next_line_help = true,
    term_width = 80,
    disable_help_flag = true,
    disable_help_subcommand = true,
    display_order = 0,
)]
pub struct LeanNode {
    #[clap(
        long,
        value_name = "CONFIG_YAML",
        help = "Path to the chain config.yaml file",
        display_order = 0
    )]
    pub config: PathBuf,

    #[clap(
        long,
        value_name = "VALIDATOR_CONFIG_YAML",
        help = "Path to the validator-config.yaml file",
        display_order = 1
    )]
    pub validators: PathBuf,

    #[clap(
        long,
        value_name = "NODES_YAML",
        help = "Path to the nodes.yaml file for bootnodes",
        display_order = 2
    )]
    pub nodes: PathBuf,

    #[clap(
        long,
        value_name = "NODE_ID",
        help = "Node identifier (e.g., 'lighthouse_0')",
        display_order = 3
    )]
    pub node_id: String,

    #[clap(
        long,
        value_name = "PRIVATE_KEY",
        help = "Path to the hex encoded secp256k1 libp2p private key",
        display_order = 4
    )]
    pub private_key: PathBuf,

    #[clap(
        long,
        value_name = "SOCKET_PORT",
        help = "P2P socket port (QUIC)",
        display_order = 5
    )]
    pub socket_port: u16,

    #[clap(
        long,
        value_name = "GENESIS_JSON",
        help = "Path to the genesis.json file",
        display_order = 6
    )]
    pub genesis_json: Option<PathBuf>,

    /* Prometheus metrics HTTP server related arguments */
    #[clap(
        long,
        help = "Enable the Prometheus metrics HTTP server. Disabled by default.",
        display_order = 6,
        help_heading = FLAG_HEADER
    )]
    pub metrics: bool,
}
