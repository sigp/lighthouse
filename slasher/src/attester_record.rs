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
pub struct IndexedAttestationHeader<T: EthSpec> {
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
