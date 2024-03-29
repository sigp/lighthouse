use crate::*;
use serde::{Deserialize, Serialize};

#[derive(arbitrary::Arbitrary, Debug, PartialEq, Clone, Copy, Default, Serialize, Deserialize)]
pub struct AttestationDuty {
    /// The slot during which the attester must attest.
    pub slot: Slot,
    /// The index of this committee within the committees in `slot`.
    pub index: CommitteeIndex,
    /// The position of the attester within the committee.
    pub committee_position: usize,
    /// The total number of attesters in the committee.
    pub committee_len: usize,
    /// The committee count at `attestation_slot`.
    #[serde(with = "serde_utils::quoted_u64")]
    pub committees_at_slot: u64,
}
