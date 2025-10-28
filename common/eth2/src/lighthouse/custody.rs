use serde::{Deserialize, Serialize};
use types::Slot;

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct CustodyInfo {
    pub earliest_custodied_data_column_slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub custody_group_count: u64,
    #[serde(with = "serde_utils::quoted_u64_vec")]
    pub custody_columns: Vec<u64>,
}
