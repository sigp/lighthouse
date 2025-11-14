use lean_crypto::Signature;

use types::BitList;
use types::EthSpec;
use types::Hash256;
use types::VariableList;
use types::typenum::U4096;

use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;


#[derive(Clone, TreeHash)]
pub struct Attestation {
    pub validator_id: u64,
    pub attestation_data: AttestationData,
}

#[derive(Clone, TreeHash)]
pub struct AttestationData {
    pub slot: Slot,
    pub head: Checkpoint,
    pub target: Checkpoint,
    pub source: Checkpoint,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Slot(pub u64);

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

impl TreeHash for Slot {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Basic
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        u64::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Hash256 {
        self.0.tree_hash_root()
    }
}

#[derive(Clone, Default, TreeHash)]
pub struct Checkpoint {
    pub slot: Slot,
    pub root: Hash256,
}


pub struct SignedAttestation {
    pub message: Attestation,
    pub signature: Signature,
}
pub struct AggregatedAttestations<E: EthSpec> {
    pub aggregation_bits: BitList<E::MaxValidatorsPerCommittee>,
    pub data: AttestationData,
}
pub struct SignedAggregatedAttestations<E: EthSpec> {
    pub aggregate_attestation: AggregatedAttestations<E>,
    pub signature: VariableList<Signature, U4096>,
}
