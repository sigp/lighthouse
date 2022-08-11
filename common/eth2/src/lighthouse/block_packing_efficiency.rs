use serde::{Deserialize, Serialize};
use types::{Epoch, Hash256, Slot};

type CommitteePosition = usize;
type Committee = u64;
type ValidatorIndex = u64;

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct UniqueAttestation {
    pub slot: Slot,
    pub committee_index: Committee,
    pub committee_position: CommitteePosition,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProposerInfo {
    pub validator_index: ValidatorIndex,
    pub graffiti: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockPackingEfficiency {
    pub slot: Slot,
    pub block_hash: Hash256,
    pub proposer_info: ProposerInfo,
    pub available_attestations: usize,
    pub included_attestations: usize,
    pub prior_skip_slots: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockPackingEfficiencyQuery {
    pub start_epoch: Epoch,
    pub end_epoch: Epoch,
}
