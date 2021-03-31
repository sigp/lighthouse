use lazy_static::lazy_static;
use parking_lot::RwLock;
use types::{ChainSpec, Hash256, Slot};

lazy_static! {
    pub static ref GENESIS_FORK: RwLock<Option<Context>> = RwLock::new(None);
    pub static ref ALTAIR_FORK: RwLock<Option<Context>> = RwLock::new(None);
}

pub struct Context([u8; 4]);

impl Context {
    pub fn new(fork_version: [u8; 4], genesis_validators_root: Hash256) -> [u8; 4] {
        ChainSpec::compute_fork_digest(fork_version, genesis_validators_root)
    }
}

impl Into<[u8; 4]> for Context {
    fn into(self) -> [u8; 4] {
        self.0
    }
}
