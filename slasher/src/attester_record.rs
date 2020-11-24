use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash as _;
use tree_hash_derive::TreeHash;
use types::{AggregateSignature, EthSpec, Hash256, IndexedAttestation, VariableList};

#[derive(Debug, Clone, Copy, Encode, Decode)]
pub struct AttesterRecord {
    /// The hash of the attestation data, for checking double-voting.
    pub attestation_data_hash: Hash256,
    /// The hash of the indexed attestation, so it can be loaded.
    pub indexed_attestation_hash: Hash256,
}

#[derive(Debug, Clone, Encode, Decode, TreeHash)]
struct IndexedAttestationHeader<T: EthSpec> {
    pub attesting_indices: VariableList<u64, T::MaxValidatorsPerCommittee>,
    pub data_root: Hash256,
    pub signature: AggregateSignature,
}

impl<T: EthSpec> From<IndexedAttestation<T>> for AttesterRecord {
    fn from(indexed_attestation: IndexedAttestation<T>) -> AttesterRecord {
        let attestation_data_hash = indexed_attestation.data.tree_hash_root();
        let header = IndexedAttestationHeader::<T> {
            attesting_indices: indexed_attestation.attesting_indices,
            data_root: attestation_data_hash,
            signature: indexed_attestation.signature,
        };
        let indexed_attestation_hash = header.tree_hash_root();
        AttesterRecord {
            attestation_data_hash,
            indexed_attestation_hash,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::indexed_att;

    // Check correctness of fast hashing
    #[test]
    fn fast_hash() {
        let data = vec![
            indexed_att(vec![], 0, 0, 0),
            indexed_att(vec![1, 2, 3], 12, 14, 1),
            indexed_att(vec![4], 0, 5, u64::MAX),
        ];
        for att in data {
            assert_eq!(
                att.tree_hash_root(),
                AttesterRecord::from(att).indexed_attestation_hash
            );
        }
    }
}
