use beacon_chain::BeaconChain;
use db::ClientDB;
use parking_lot::RwLock;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::{BeaconBlock, FreeAttestation};

mod attester;
mod producer;

pub struct BenchingBeaconNode<T: ClientDB, U: SlotClock> {
    beacon_chain: Arc<BeaconChain<T, U>>,
    published_blocks: RwLock<Vec<BeaconBlock>>,
    published_attestations: RwLock<Vec<FreeAttestation>>,
}

impl<T: ClientDB, U: SlotClock> BenchingBeaconNode<T, U> {
    pub fn new(beacon_chain: Arc<BeaconChain<T, U>>) -> Self {
        Self {
            beacon_chain,
            published_blocks: RwLock::new(vec![]),
            published_attestations: RwLock::new(vec![]),
        }
    }

    pub fn last_published_block(&self) -> Option<BeaconBlock> {
        Some(self.published_blocks.read().last()?.clone())
    }

    pub fn last_published_free_attestation(&self) -> Option<FreeAttestation> {
        Some(self.published_attestations.read().last()?.clone())
    }
}
