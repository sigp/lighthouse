use serde::{Deserialize, Serialize};
use types::{Hash256, Slot};

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct BlobsVerificationData {
    pub block_root: Hash256,
    pub slot: Slot,
    pub blobs_exist: bool,
    pub blobs_stored: bool,
    pub blobs_verified: bool,
}
