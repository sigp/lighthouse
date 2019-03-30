use crate::*;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Copy, Default, Serialize, Deserialize)]
pub struct AttestationDuty {
    pub slot: Slot,
    pub shard: Shard,
    pub committee_index: usize,
    pub committee_len: usize,
}
