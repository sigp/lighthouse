use crate::test_utils::TestRandom;
use crate::{
    beacon_block_body::BLOB_KZG_COMMITMENTS_INDEX, BeaconBlockHeader, BeaconStateError, Blob,
    EthSpec, FixedVector, Hash256, SignedBeaconBlockHeader, Slot, VariableList,
};
use crate::{KzgProofs, SignedBeaconBlock};
use bls::Signature;
use derivative::Derivative;
use kzg::{Blob as KzgBlob, Kzg, KzgCommitment, KzgProof, BYTES_PER_BLOB, BYTES_PER_FIELD_ELEMENT};
use merkle_proof::{merkle_root_from_branch, verify_merkle_proof, MerkleTreeError};
use rand::Rng;
use safe_arith::ArithError;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

/// Container of the data that identifies an individual blob.
#[derive(
    Serialize, Deserialize, Encode, Decode, TreeHash, Copy, Clone, Debug, PartialEq, Eq, Hash,
)]
pub struct BlobIdentifier {
    pub block_root: Hash256,
    pub index: u64,
}

impl BlobIdentifier {
    pub fn get_all_blob_ids<E: EthSpec>(block_root: Hash256) -> Vec<BlobIdentifier> {
        let mut blob_ids = Vec::with_capacity(E::max_blobs_per_block());
        for i in 0..E::max_blobs_per_block() {
            blob_ids.push(BlobIdentifier {
                block_root,
                index: i as u64,
            });
        }
        blob_ids
    }
}

impl PartialOrd for BlobIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
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
    TestRandom,
    Derivative,
    arbitrary::Arbitrary,
)]
#[serde(bound = "E: EthSpec")]
#[arbitrary(bound = "E: EthSpec")]
#[derivative(PartialEq, Eq, Hash(bound = "E: EthSpec"))]
pub struct BlobSidecar<E: EthSpec> {
    #[serde(with = "serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub blob: Blob<E>,
    pub kzg_commitment: KzgCommitment,
    pub kzg_proof: KzgProof,
    pub signed_block_header: SignedBeaconBlockHeader,
    pub kzg_commitment_inclusion_proof: FixedVector<Hash256, E::KzgCommitmentInclusionProofDepth>,
}

impl<E: EthSpec> PartialOrd for BlobSidecar<E> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: EthSpec> Ord for BlobSidecar<E> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index.cmp(&other.index)
    }
}

#[derive(Debug)]
pub enum BlobSidecarError {
    PreDeneb,
    MissingKzgCommitment,
    BeaconState(BeaconStateError),
    MerkleTree(MerkleTreeError),
    ArithError(ArithError),
}

impl From<BeaconStateError> for BlobSidecarError {
    fn from(e: BeaconStateError) -> Self {
        BlobSidecarError::BeaconState(e)
    }
}

impl From<MerkleTreeError> for BlobSidecarError {
    fn from(e: MerkleTreeError) -> Self {
        BlobSidecarError::MerkleTree(e)
    }
}

impl From<ArithError> for BlobSidecarError {
    fn from(e: ArithError) -> Self {
        BlobSidecarError::ArithError(e)
    }
}

impl<E: EthSpec> BlobSidecar<E> {
    pub fn new(
        index: usize,
        blob: Blob<E>,
        signed_block: &SignedBeaconBlock<E>,
        kzg_proof: KzgProof,
    ) -> Result<Self, BlobSidecarError> {
        let expected_kzg_commitments = signed_block
            .message()
            .body()
            .blob_kzg_commitments()
            .map_err(|_e| BlobSidecarError::PreDeneb)?;
        let kzg_commitment = *expected_kzg_commitments
            .get(index)
            .ok_or(BlobSidecarError::MissingKzgCommitment)?;
        let kzg_commitment_inclusion_proof = signed_block
            .message()
            .body()
            .kzg_commitment_merkle_proof(index)?;

        Ok(Self {
            index: index as u64,
            blob,
            kzg_commitment,
            kzg_proof,
            signed_block_header: signed_block.signed_block_header(),
            kzg_commitment_inclusion_proof,
        })
    }

    pub fn id(&self) -> BlobIdentifier {
        BlobIdentifier {
            block_root: self.block_root(),
            index: self.index,
        }
    }

    pub fn slot(&self) -> Slot {
        self.signed_block_header.message.slot
    }

    pub fn block_root(&self) -> Hash256 {
        self.signed_block_header.message.tree_hash_root()
    }

    pub fn block_parent_root(&self) -> Hash256 {
        self.signed_block_header.message.parent_root
    }

    pub fn block_proposer_index(&self) -> u64 {
        self.signed_block_header.message.proposer_index
    }

    pub fn empty() -> Self {
        Self {
            index: 0,
            blob: Blob::<E>::default(),
            kzg_commitment: KzgCommitment::empty_for_testing(),
            kzg_proof: KzgProof::empty(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader::empty(),
                signature: Signature::empty(),
            },
            kzg_commitment_inclusion_proof: Default::default(),
        }
    }

    /// Verifies the kzg commitment inclusion merkle proof.
    pub fn verify_blob_sidecar_inclusion_proof(&self) -> bool {
        let kzg_commitments_tree_depth = E::kzg_commitments_tree_depth();

        // EthSpec asserts that kzg_commitments_tree_depth is less than KzgCommitmentInclusionProofDepth
        let (kzg_commitment_subtree_proof, kzg_commitments_proof) = self
            .kzg_commitment_inclusion_proof
            .split_at(kzg_commitments_tree_depth);

        // Compute the `tree_hash_root` of the `blob_kzg_commitments` subtree using the
        // inclusion proof branches
        let blob_kzg_commitments_root = merkle_root_from_branch(
            self.kzg_commitment.tree_hash_root(),
            kzg_commitment_subtree_proof,
            kzg_commitments_tree_depth,
            self.index as usize,
        );
        // The remaining inclusion proof branches are for the top level `BeaconBlockBody` tree
        verify_merkle_proof(
            blob_kzg_commitments_root,
            kzg_commitments_proof,
            E::block_body_tree_depth(),
            BLOB_KZG_COMMITMENTS_INDEX,
            self.signed_block_header.message.body_root,
        )
    }

    pub fn random_valid<R: Rng>(rng: &mut R, kzg: &Kzg) -> Result<Self, String> {
        let mut blob_bytes = vec![0u8; BYTES_PER_BLOB];
        rng.fill_bytes(&mut blob_bytes);
        // Ensure that the blob is canonical by ensuring that
        // each field element contained in the blob is < BLS_MODULUS
        for byte in blob_bytes.iter_mut().step_by(BYTES_PER_FIELD_ELEMENT) {
            *byte = 0;
        }

        let blob = Blob::<E>::new(blob_bytes)
            .map_err(|e| format!("error constructing random blob: {:?}", e))?;
        let kzg_blob = KzgBlob::from_bytes(&blob).unwrap();

        let commitment = kzg
            .blob_to_kzg_commitment(&kzg_blob)
            .map_err(|e| format!("error computing kzg commitment: {:?}", e))?;

        let proof = kzg
            .compute_blob_kzg_proof(&kzg_blob, commitment)
            .map_err(|e| format!("error computing kzg proof: {:?}", e))?;

        Ok(Self {
            blob,
            kzg_commitment: commitment,
            kzg_proof: proof,
            ..Self::empty()
        })
    }

    #[allow(clippy::arithmetic_side_effects)]
    pub fn max_size() -> usize {
        // Fixed part
        Self::empty().as_ssz_bytes().len()
    }

    pub fn build_sidecars(
        blobs: BlobsList<E>,
        block: &SignedBeaconBlock<E>,
        kzg_proofs: KzgProofs<E>,
    ) -> Result<BlobSidecarList<E>, BlobSidecarError> {
        let mut blob_sidecars = vec![];
        for (i, (kzg_proof, blob)) in kzg_proofs.iter().zip(blobs).enumerate() {
            let blob_sidecar = BlobSidecar::new(i, blob, block, *kzg_proof)?;
            blob_sidecars.push(Arc::new(blob_sidecar));
        }
        Ok(VariableList::from(blob_sidecars))
    }
}

pub type BlobSidecarList<E> = VariableList<Arc<BlobSidecar<E>>, <E as EthSpec>::MaxBlobsPerBlock>;
pub type FixedBlobSidecarList<E> =
    FixedVector<Option<Arc<BlobSidecar<E>>>, <E as EthSpec>::MaxBlobsPerBlock>;
pub type BlobsList<E> = VariableList<Blob<E>, <E as EthSpec>::MaxBlobCommitmentsPerBlock>;
