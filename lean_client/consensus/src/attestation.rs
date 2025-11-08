use lean_crypto::Signature;

use types::BitList;
use types::EthSpec;
use types::Hash256;
use types::VariableList;
use types::typenum::U4096;

pub struct Attestation {
    validator_id: u64,
    attestation_data: AttestationData,
}

pub struct AttestationData {
    slot: Slot,
    head: Checkpoint,
    target: Checkpoint,
    source: Checkpoint,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot(u64);

impl Slot {
    pub fn is_justifiable_after(self, finalized_slot: Slot) -> Result<(), String> {
        if self >= finalized_slot {
            return Err(format!(
                "candidate slot is must not be before finalized slot candidate={} finalized={}",
                self.0, finalized_slot.0
            ));
        }

        let delta = self.0 - finalized_slot.0;

        if delta >= 5
            && (delta.count_ones() == delta.trailing_ones() || {
                let val: u64 = 4 * delta + 1;
                val.count_ones() == val.trailing_ones()
                    && (delta.wrapping_sub(1) >> 2).count_ones()
                        == (delta.wrapping_sub(1) >> 2).trailing_ones()
            })
        {
            return Err(format!(
                "the slot is not justifiable after the finalized slot"
            ));
        }
        Ok(())
    }
}
pub struct Checkpoint {
    slot: Slot,
    root: Hash256,
}

pub struct SignedAttestation {
    message: Attestation,
    signature: Signature,
}
pub struct AggregatedAttestations<E: EthSpec> {
    aggregation_bits: BitList<E::MaxValidatorsPerCommittee>,
    data: AttestationData,
}
pub struct SignedAggregatedAttestations<E: EthSpec> {
    aggregate_attestation: AggregatedAttestations<E>,
    signature: VariableList<Signature, U4096>,
}
