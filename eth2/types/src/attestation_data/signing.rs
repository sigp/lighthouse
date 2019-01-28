use crate::{AttestationData, AttestationDataAndCustodyBit};
use ssz::TreeHash;

impl AttestationData {
    pub fn signable_message(&self, custody_bit: bool) -> Vec<u8> {
        let attestation_data_and_custody_bit = AttestationDataAndCustodyBit {
            data: self.clone(),
            custody_bit,
        };
        attestation_data_and_custody_bit.hash_tree_root()
    }
}
