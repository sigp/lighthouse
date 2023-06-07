use crate::test_utils::TestRandom;
use crate::{Blob, ChainSpec, Domain, EthSpec, Fork, Hash256, SignedBlobSidecar, SignedRoot, Slot};
use bls::SecretKey;
use derivative::Derivative;
use kzg::{KzgCommitment, KzgProof};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash_derive::TreeHash;

/// Container of the data that identifies an individual blob.
#[derive(
    Serialize, Deserialize, Encode, Decode, TreeHash, Copy, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct BlobIdentifier {
    pub block_root: Hash256,
    pub index: u64,
}

impl PartialOrd for BlobIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.index.partial_cmp(&other.index)
    }
}

impl Ord for BlobIdentifier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index.cmp(&other.index)
    }
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    Default,
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
#[derivative(PartialEq, Eq, Hash(bound = "T: EthSpec"))]
pub struct BlobSidecar<T: EthSpec> {
    pub block_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    pub slot: Slot,
    pub block_parent_root: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    pub proposer_index: u64,
    pub blob: Blob,
    pub kzg_commitment: KzgCommitment,
    pub kzg_proof: KzgProof,
    #[serde(skip)]
    #[ssz(skip_serializing, skip_deserializing)]
    #[tree_hash(skip_hashing)]
    pub _phantom: std::marker::PhantomData<T>,
}

impl<T: EthSpec> PartialOrd for BlobSidecar<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.index.partial_cmp(&other.index)
    }
}

impl<T: EthSpec> Ord for BlobSidecar<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index.cmp(&other.index)
    }
}

pub type BlobSidecarList<T> = VariableList<Arc<BlobSidecar<T>>, <T as EthSpec>::MaxBlobsPerBlock>;
pub type FixedBlobSidecarList<T> =
    FixedVector<Option<Arc<BlobSidecar<T>>>, <T as EthSpec>::MaxBlobsPerBlock>;
pub type Blobs<E> = VariableList<Blob, <E as EthSpec>::MaxBlobsPerBlock>;

impl<T: EthSpec> SignedRoot for BlobSidecar<T> {}

impl<T: EthSpec> BlobSidecar<T> {
    pub fn id(&self) -> BlobIdentifier {
        BlobIdentifier {
            block_root: self.block_root,
            index: self.index,
        }
    }

    pub fn empty() -> Self {
        Self::default()
    }

    #[allow(clippy::integer_arithmetic)]
    pub fn max_size() -> usize {
        // Fixed part
        Self::empty().as_ssz_bytes().len()
    }

    // this is mostly not used except for in testing
    pub fn sign(
        self: Arc<Self>,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedBlobSidecar<T> {
        let signing_epoch = self.slot.epoch(T::slots_per_epoch());
        let domain = spec.get_domain(
            signing_epoch,
            Domain::BlobSidecar,
            fork,
            genesis_validators_root,
        );
        let message = self.signing_root(domain);
        let signature = secret_key.sign(message);

        SignedBlobSidecar {
            message: self,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EthSpec;
    use ssz::{Decode, Encode};
    use tree_hash::TreeHash;

    type OldBlob<T> = FixedVector<u8, <T as EthSpec>::BytesPerBlob>;
    #[cfg(feature = "spec-minimal")]
    type E = crate::MinimalEthSpec;
    #[cfg(not(feature = "spec-minimal"))]
    type E = crate::MainnetEthSpec;

    #[derive(
        Debug,
        Clone,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        TreeHash,
        Default,
        TestRandom,
        Derivative,
        arbitrary::Arbitrary,
    )]
    #[serde(bound = "E: EthSpec")]
    #[arbitrary(bound = "E: EthSpec")]
    #[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
    pub struct OldBlobSidecar<E: EthSpec> {
        pub block_root: Hash256,
        #[serde(with = "serde_utils::quoted_u64")]
        pub index: u64,
        pub slot: Slot,
        pub block_parent_root: Hash256,
        #[serde(with = "serde_utils::quoted_u64")]
        pub proposer_index: u64,
        #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
        pub blob: OldBlob<E>,
        pub kzg_commitment: KzgCommitment,
        pub kzg_proof: KzgProof,
    }

    impl<E: EthSpec> OldBlobSidecar<E> {
        fn from_new_sidecar(new_sidecar: &BlobSidecar<E>) -> Self {
            let old_blob = OldBlob::<E>::new(Vec::from(new_sidecar.blob.as_ref())).unwrap();
            Self {
                block_root: new_sidecar.block_root,
                index: new_sidecar.index,
                slot: new_sidecar.slot,
                block_parent_root: new_sidecar.block_parent_root,
                proposer_index: new_sidecar.proposer_index,
                blob: old_blob,
                kzg_commitment: new_sidecar.kzg_commitment,
                kzg_proof: new_sidecar.kzg_proof,
            }
        }
    }

    fn same_bytes(a: &[u8], b: &[u8]) -> bool {
        a.iter().zip(b.iter()).all(|(a, b)| a == b)
    }

    #[test]
    fn ssz_equivalence() {
        let new_sidecar = BlobSidecar::random_for_test(&mut rand::thread_rng());
        let old_sidecar = OldBlobSidecar::<E>::from_new_sidecar(&new_sidecar);

        // test that the blobs have the same bytes
        assert!(
            same_bytes(new_sidecar.blob.as_ref(), old_sidecar.blob.as_ref()),
            "blobs should have the same bytes"
        );

        // test that their ssz encodings are the same
        assert_eq!(
            new_sidecar.as_ssz_bytes(),
            old_sidecar.as_ssz_bytes(),
            "ssz encoding of new and old sidecars should be the same"
        );
        // test that you can recover the old sidecar from the new one
        let recovered_old_sidecar =
            OldBlobSidecar::<E>::from_ssz_bytes(&new_sidecar.as_ssz_bytes()).unwrap();
        assert_eq!(
            recovered_old_sidecar, old_sidecar,
            "recovered old sidecar should be the same as the old sidecar"
        );
        // test that you can recover the new sidecar from the old one
        let recovered_new_sidecar =
            BlobSidecar::<E>::from_ssz_bytes(&old_sidecar.as_ssz_bytes()).unwrap();
        assert_eq!(
            recovered_new_sidecar, new_sidecar,
            "recovered new sidecar should be the same as the new sidecar"
        );
    }

    #[test]
    fn tree_hash_equivalence() {
        let new_sidecar = BlobSidecar::random_for_test(&mut rand::thread_rng());
        let old_sidecar = OldBlobSidecar::<E>::from_new_sidecar(&new_sidecar);

        // test that their tree hashes are the same
        assert_eq!(
            new_sidecar.tree_hash_root(),
            old_sidecar.tree_hash_root(),
            "tree hash of new and old sidecars should be the same"
        );
    }

    #[test]
    fn serde_equivalence() {
        let new_sidecar = BlobSidecar::random_for_test(&mut rand::thread_rng());
        let old_sidecar = OldBlobSidecar::<E>::from_new_sidecar(&new_sidecar);

        // test that the blobs have the same bytes
        assert!(
            same_bytes(new_sidecar.blob.as_ref(), old_sidecar.blob.as_ref()),
            "blobs should have the same bytes"
        );

        // test that their serde encodings are the same
        assert_eq!(
            serde_json::to_string(&new_sidecar).unwrap(),
            serde_json::to_string(&old_sidecar).unwrap(),
            "serde encoding of new and old sidecars should be the same"
        );
        // test that you can recover the old sidecar from the new one
        let recovered_old_sidecar: OldBlobSidecar<E> =
            serde_json::from_str(&serde_json::to_string(&new_sidecar).unwrap()).unwrap();
        assert_eq!(
            recovered_old_sidecar, old_sidecar,
            "recovered old sidecar should be the same as the old sidecar"
        );
        // test that you can recover the new sidecar from the old one
        let recovered_new_sidecar: BlobSidecar<E> =
            serde_json::from_str(&serde_json::to_string(&old_sidecar).unwrap()).unwrap();
        assert_eq!(
            recovered_new_sidecar, new_sidecar,
            "recovered new sidecar should be the same as the new sidecar"
        );
    }

    ssz_and_tree_hash_tests!(BlobSidecar<E>);
}
