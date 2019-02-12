mod attestation_aggregator;
mod beacon_chain;
mod block_graph;
mod checkpoint;

pub use self::beacon_chain::{BeaconChain, Error};
pub use self::checkpoint::CheckPoint;
