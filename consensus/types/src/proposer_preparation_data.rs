use crate::*;
use serde::{Deserialize, Serialize};

/// A proposer preparation, created when a validator prepares the beacon node for potential proposers
/// by supplying information required when proposing blocks for the given validators.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProposerPreparationData {
    /// The validators index.
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub validator_index: u64,
    /// The fee-recipient address.
    pub fee_recipient: Address,
}
