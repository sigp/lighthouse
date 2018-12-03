use super::{AttestationData, Bitfield};

#[derive(Debug, Clone, PartialEq)]
pub struct PendingAttestationRecord {
    pub data: AttestationData,
    pub participation_bitfield: Bitfield,
    pub custody_bitfield: Bitfield,
    pub slot_included: u64,
}
