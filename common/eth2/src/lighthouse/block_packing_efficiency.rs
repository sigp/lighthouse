use serde::{Deserialize, Serialize};
use types::{Epoch, Hash256, Slot};

type CommitteePosition = usize;
type Committee = u64;
type ValidatorIndex = u64;

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct UniqueAttestation {
    pub slot: Slot,
    pub committee_index: Committee,
    pub committee_position: CommitteePosition,
}
#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct ProposerInfo {
    pub validator_index: ValidatorIndex,
    pub graffiti: String,
}

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct BlockPackingEfficiency {
    pub slot: Slot,
    pub block_hash: Hash256,
    pub proposer_info: ProposerInfo,
    pub available_attestations: usize,
    pub included_attestations: usize,
    pub prior_skip_slots: u64,
}

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub struct BlockPackingEfficiencyQuery {
    pub start_epoch: Epoch,
    pub end_epoch: Epoch,
}
