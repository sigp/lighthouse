use crate::{database::IndexedAttestationId, Error};
use ssz_derive::{Decode, Encode};
use std::borrow::Cow;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tree_hash::TreeHash as _;
use tree_hash_derive::TreeHash;
use types::{AggregateSignature, EthSpec, Hash256, IndexedAttestation, VariableList};

#[derive(Debug, Clone, Copy)]
pub struct AttesterRecord {
    /// The hash of the attestation data, for de-duplication.
    pub attestation_data_hash: Hash256,
    /// The hash of the indexed attestation, so it can be loaded.
    pub indexed_attestation_hash: Hash256,
}

#[derive(Debug, Clone, Copy)]
pub struct CompactAttesterRecord {
    /// The ID of the `IndexedAttestation` signed by this validator.
    pub indexed_attestation_id: IndexedAttestationId,
}

impl CompactAttesterRecord {
    pub fn new(indexed_attestation_id: IndexedAttestationId) -> Self {
        Self {
            indexed_attestation_id,
        }
    }

    pub fn null() -> Self {
        Self::new(IndexedAttestationId::null())
    }

    pub fn parse(bytes: Cow<[u8]>) -> Result<Self, Error> {
        let id = IndexedAttestationId::parse(bytes)?;
        Ok(Self::new(IndexedAttestationId::new(id)))
    }

    pub fn is_null(&self) -> bool {
        self.indexed_attestation_id.is_null()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.indexed_attestation_id.as_ref()
    }
}

/// Bundling of an `IndexedAttestation` with an `AttesterRecord`.
///
/// This struct gets `Arc`d and passed around between each stage of queueing and processing.
#[derive(Debug)]
pub struct IndexedAttesterRecord<E: EthSpec> {
    pub indexed: IndexedAttestation<E>,
    pub record: AttesterRecord,
    pub indexed_attestation_id: AtomicU64,
}

impl<E: EthSpec> IndexedAttesterRecord<E> {
    pub fn new(indexed: IndexedAttestation<E>, record: AttesterRecord) -> Arc<Self> {
        Arc::new(IndexedAttesterRecord {
            indexed,
            record,
            indexed_attestation_id: AtomicU64::new(0),
        })
    }

    pub fn set_id(&self, id: u64) {
        self.indexed_attestation_id
            .compare_exchange(0, id, Ordering::Relaxed, Ordering::Relaxed)
            .expect("IDs should only be initialized once");
    }

    pub fn get_id(&self) -> u64 {
        self.indexed_attestation_id.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Encode, Decode, TreeHash)]
struct IndexedAttestationHeader<E: EthSpec> {
    pub attesting_indices: VariableList<u64, E::MaxValidatorsPerSlot>,
    pub data_root: Hash256,
    pub signature: AggregateSignature,
}

impl<E: EthSpec> From<IndexedAttestation<E>> for AttesterRecord {
    fn from(indexed_attestation: IndexedAttestation<E>) -> AttesterRecord {
        let attestation_data_hash = indexed_attestation.data().tree_hash_root();
        let attesting_indices =
            VariableList::new(indexed_attestation.attesting_indices_to_vec()).unwrap_or_default();
        let header = IndexedAttestationHeader::<E> {
            attesting_indices,
            data_root: attestation_data_hash,
            signature: indexed_attestation.signature().clone(),
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
    use crate::test_utils::indexed_att_electra;

    // Check correctness of fast hashing
    #[test]
    fn fast_hash() {
        let data = vec![
            indexed_att_electra(vec![], 0, 0, 0),
            indexed_att_electra(vec![1, 2, 3], 12, 14, 1),
            indexed_att_electra(vec![4], 0, 5, u64::MAX),
        ];
        for att in data {
            assert_eq!(
                att.tree_hash_root(),
                AttesterRecord::from(att).indexed_attestation_hash
            );
        }
    }
}
