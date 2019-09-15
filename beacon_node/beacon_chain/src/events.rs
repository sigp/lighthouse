use serde_derive::{Deserialize, Serialize};
use std::marker::PhantomData;
use types::{Attestation, BeaconBlock, Epoch, EthSpec, Hash256};

pub trait EventHandler<T: EthSpec>: Sized + Send + Sync {
    fn register(&self, kind: EventKind<T>) -> Result<(), String>;
}

pub struct NullEventHandler<T: EthSpec>(PhantomData<T>);

impl<T: EthSpec> EventHandler<T> for NullEventHandler<T> {
    fn register(&self, _kind: EventKind<T>) -> Result<(), String> {
        Ok(())
    }
}

impl<T: EthSpec> Default for NullEventHandler<T> {
    fn default() -> Self {
        NullEventHandler(PhantomData)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    bound = "T: EthSpec",
    rename_all = "snake_case",
    tag = "event",
    content = "data"
)]
pub enum EventKind<T: EthSpec> {
    BeaconHeadChanged {
        reorg: bool,
        current_head_beacon_block_root: Hash256,
        previous_head_beacon_block_root: Hash256,
    },
    BeaconFinalization {
        epoch: Epoch,
        root: Hash256,
    },
    BeaconBlockImported {
        block_root: Hash256,
        block: Box<BeaconBlock<T>>,
    },
    BeaconBlockRejected {
        reason: String,
        block: Box<BeaconBlock<T>>,
    },
    BeaconAttestationImported {
        attestation: Box<Attestation<T>>,
    },
    BeaconAttestationRejected {
        reason: String,
        attestation: Box<Attestation<T>>,
    },
}
