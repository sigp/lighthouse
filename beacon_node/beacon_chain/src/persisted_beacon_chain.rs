use crate::head_tracker::SszHeadTracker;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error as StoreError, StoreItem};
use types::Hash256;

/// Dummy value to use for the canonical head block root, see below.
pub const DUMMY_CANONICAL_HEAD_BLOCK_ROOT: Hash256 = Hash256::repeat_byte(0xff);

#[derive(Clone, Encode, Decode)]
pub struct PersistedBeaconChain {
    /// This value is ignored to resolve the issue described here:
    ///
    /// https://github.com/sigp/lighthouse/pull/1639
    ///
    /// Its removal is tracked here:
    ///
    /// https://github.com/sigp/lighthouse/issues/1784
    pub _canonical_head_block_root: Hash256,
    pub genesis_block_root: Hash256,
    pub ssz_head_tracker: SszHeadTracker,
}

impl StoreItem for PersistedBeaconChain {
    fn db_column() -> DBColumn {
        DBColumn::BeaconChain
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
