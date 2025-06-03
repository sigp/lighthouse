use serde::{Deserialize, Serialize};

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct BlobsVerificationData {
    pub blob_count: usize,
    pub blobs_missing: Vec<u64>,
    pub blobs_invalid: Vec<u64>,
}
