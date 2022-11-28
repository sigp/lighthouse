use super::*;
use crate::decode::{ssz_decode_state, yaml_decode_file};
use serde_derive::Deserialize;
use std::path::Path;
use tree_hash::Hash256;
use types::{BeaconState, EthSpec, ForkName};

#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    #[serde(rename(deserialize = "description"))]
    _description: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MerkleProof {
    pub leaf: Hash256,
    pub leaf_index: usize,
    pub branch: Vec<Hash256>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct MerkleProofValidity<E: EthSpec> {
    pub metadata: Option<Metadata>,
    pub state: BeaconState<E>,
    pub merkle_proof: MerkleProof,
}

impl<E: EthSpec> LoadCase for MerkleProofValidity<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = &testing_spec::<E>(fork_name);
        let state = ssz_decode_state(&path.join("state.ssz_snappy"), spec)?;
        let merkle_proof = yaml_decode_file(&path.join("proof.yaml"))?;
        // Metadata does not exist in these tests but it is left like this just in case.
        let meta_path = path.join("meta.yaml");
        let metadata = if meta_path.exists() {
            Some(yaml_decode_file(&meta_path)?)
        } else {
            None
        };

        Ok(Self {
            metadata,
            state,
            merkle_proof,
        })
    }
}

impl<E: EthSpec> Case for MerkleProofValidity<E> {
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let mut state = self.state.clone();
        state.initialize_tree_hash_cache();
        let proof = match state.compute_merkle_proof(self.merkle_proof.leaf_index) {
            Ok(proof) => proof,
            Err(_) => {
                return Err(Error::FailedToParseTest(
                    "Could not retrieve merkle proof".to_string(),
                ))
            }
        };
        let proof_len = proof.len();
        let branch_len = self.merkle_proof.branch.len();
        if proof_len != branch_len {
            return Err(Error::NotEqual(format!(
                "Branches not equal in length computed: {}, expected {}",
                proof_len, branch_len
            )));
        }

        for (i, proof_leaf) in proof.iter().enumerate().take(proof_len) {
            let expected_leaf = self.merkle_proof.branch[i];
            if *proof_leaf != expected_leaf {
                return Err(Error::NotEqual(format!(
                    "Leaves not equal in merke proof computed: {}, expected: {}",
                    hex::encode(proof_leaf),
                    hex::encode(expected_leaf)
                )));
            }
        }

        // Tree hash cache should still be initialized (not dropped).
        assert!(state.tree_hash_cache().is_initialized());

        Ok(())
    }
}
