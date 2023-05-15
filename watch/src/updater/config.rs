use serde::{Deserialize, Serialize};

pub const BEACON_NODE_URL: &str = "http://127.0.0.1:5052";

pub const fn max_backfill_size_epochs() -> u64 {
    2
}
pub const fn backfill_stop_epoch() -> u64 {
    0
}
pub const fn attestations() -> bool {
    true
}
pub const fn proposer_info() -> bool {
    true
}
pub const fn block_rewards() -> bool {
    true
}
pub const fn block_packing() -> bool {
    true
}

fn beacon_node_url() -> String {
    BEACON_NODE_URL.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The URL of the beacon you wish to sync from.
    #[serde(default = "beacon_node_url")]
    pub beacon_node_url: String,
    /// The maximum size each backfill iteration will allow per request (in epochs).
    #[serde(default = "max_backfill_size_epochs")]
    pub max_backfill_size_epochs: u64,
    /// The epoch at which to never backfill past.
    #[serde(default = "backfill_stop_epoch")]
    pub backfill_stop_epoch: u64,
    /// Whether to sync the suboptimal_attestations table.
    #[serde(default = "attestations")]
    pub attestations: bool,
    /// Whether to sync the proposer_info table.
    #[serde(default = "proposer_info")]
    pub proposer_info: bool,
    /// Whether to sync the block_rewards table.
    #[serde(default = "block_rewards")]
    pub block_rewards: bool,
    /// Whether to sync the block_packing table.
    #[serde(default = "block_packing")]
    pub block_packing: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            beacon_node_url: beacon_node_url(),
            max_backfill_size_epochs: max_backfill_size_epochs(),
            backfill_stop_epoch: backfill_stop_epoch(),
            attestations: attestations(),
            proposer_info: proposer_info(),
            block_rewards: block_rewards(),
            block_packing: block_packing(),
        }
    }
}
