use crate::{Attestation, AttestationDataAndCustodyBit};
use ssz::TreeHash;

impl Attestation {
    pub fn signable_message(&self) -> Vec<u8> {
        let attestation_data_and_custody_bit = AttestationDataAndCustodyBit {
            data: self.data.clone(),
            custody_bit: false,
        };
        attestation_data_and_custody_bit.hash_tree_root()
    }
}
