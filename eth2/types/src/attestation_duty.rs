use crate::*;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Default, Serialize, Deserialize)]
pub struct AttestationDuty {
    pub slot: Slot,
    pub shard: Shard,
    pub committee_index: usize,
    pub validator_index: usize,
}
