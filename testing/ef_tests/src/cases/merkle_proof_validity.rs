use super::*;
use crate::decode::{ssz_decode_file, ssz_decode_state, yaml_decode_file};
use serde::Deserialize;
use tree_hash::Hash256;
use types::{
    light_client_update, BeaconBlockBody, BeaconBlockBodyCapella, BeaconBlockBodyDeneb,
    BeaconBlockBodyElectra, BeaconState, FixedVector, FullPayload, Unsigned,
};

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
pub struct BeaconStateMerkleProofValidity<E: EthSpec> {
    pub metadata: Option<Metadata>,
    pub state: BeaconState<E>,
    pub merkle_proof: MerkleProof,
}

impl<E: EthSpec> LoadCase for BeaconStateMerkleProofValidity<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let spec = &testing_spec::<E>(fork_name);
        let state = ssz_decode_state(&path.join("object.ssz_snappy"), spec)?;
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

impl<E: EthSpec> Case for BeaconStateMerkleProofValidity<E> {
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let mut state = self.state.clone();
        state.update_tree_hash_cache().unwrap();

        let proof = match self.merkle_proof.leaf_index {
            light_client_update::CURRENT_SYNC_COMMITTEE_INDEX_ELECTRA
            | light_client_update::CURRENT_SYNC_COMMITTEE_INDEX => {
                state.compute_current_sync_committee_proof()
            }
            light_client_update::NEXT_SYNC_COMMITTEE_INDEX_ELECTRA
            | light_client_update::NEXT_SYNC_COMMITTEE_INDEX => {
                state.compute_next_sync_committee_proof()
            }
            light_client_update::FINALIZED_ROOT_INDEX_ELECTRA
            | light_client_update::FINALIZED_ROOT_INDEX => state.compute_finalized_root_proof(),
            _ => {
                return Err(Error::FailedToParseTest(
                    "Could not retrieve merkle proof, invalid index".to_string(),
                ));
            }
        };

        let Ok(proof) = proof else {
            return Err(Error::FailedToParseTest(
                "Could not retrieve merkle proof".to_string(),
            ));
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

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct KzgInclusionMerkleProofValidity<E: EthSpec> {
    pub metadata: Option<Metadata>,
    pub block: BeaconBlockBody<E>,
    pub merkle_proof: MerkleProof,
    pub proof_type: KzgInclusionProofType,
}

#[derive(Debug, Clone)]
pub enum KzgInclusionProofType {
    Single,
    List,
}

impl<E: EthSpec> LoadCase for KzgInclusionMerkleProofValidity<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let block: BeaconBlockBody<E, FullPayload<E>> = match fork_name {
            ForkName::Base | ForkName::Altair | ForkName::Bellatrix | ForkName::Capella => {
                return Err(Error::InternalError(format!(
                    "KZG inclusion merkle proof validity test skipped for {:?}",
                    fork_name
                )))
            }
            ForkName::Deneb => {
                ssz_decode_file::<BeaconBlockBodyDeneb<E>>(&path.join("object.ssz_snappy"))?.into()
            }
            ForkName::Electra => {
                ssz_decode_file::<BeaconBlockBodyElectra<E>>(&path.join("object.ssz_snappy"))?
                    .into()
            }
        };
        let merkle_proof = yaml_decode_file(&path.join("proof.yaml"))?;
        // Metadata does not exist in these tests but it is left like this just in case.
        let meta_path = path.join("meta.yaml");
        let metadata = if meta_path.exists() {
            Some(yaml_decode_file(&meta_path)?)
        } else {
            None
        };

        let file_name = path
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .ok_or(Error::InternalError(
                "failed to read file name from path".to_string(),
            ))?;

        let proof_type = if file_name.starts_with("blob_kzg_commitments") {
            KzgInclusionProofType::List
        } else {
            KzgInclusionProofType::Single
        };

        Ok(Self {
            metadata,
            block,
            merkle_proof,
            proof_type,
        })
    }
}

impl<E: EthSpec> KzgInclusionMerkleProofValidity<E> {
    fn verify_kzg_inclusion_proof<N: Unsigned>(
        &self,
        proof: FixedVector<Hash256, N>,
    ) -> Result<(), Error> {
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
                    "Leaves not equal in merkle proof computed: {}, expected: {}",
                    hex::encode(proof_leaf),
                    hex::encode(expected_leaf)
                )));
            }
        }

        Ok(())
    }
}
impl<E: EthSpec> Case for KzgInclusionMerkleProofValidity<E> {
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        match self.proof_type {
            KzgInclusionProofType::Single => {
                let proof = self
                    .block
                    .to_ref()
                    .kzg_commitment_merkle_proof(0)
                    .map_err(|e| {
                        Error::FailedToParseTest(format!("Could not retrieve merkle proof: {e:?}"))
                    })?;
                self.verify_kzg_inclusion_proof(proof)
            }
            KzgInclusionProofType::List => {
                let proof = self
                    .block
                    .to_ref()
                    .kzg_commitments_merkle_proof()
                    .map_err(|e| {
                        Error::FailedToParseTest(format!("Could not retrieve merkle proof: {e:?}"))
                    })?;
                self.verify_kzg_inclusion_proof(proof)
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct BeaconBlockBodyMerkleProofValidity<E: EthSpec> {
    pub metadata: Option<Metadata>,
    pub block_body: BeaconBlockBody<E, FullPayload<E>>,
    pub merkle_proof: MerkleProof,
}

impl<E: EthSpec> LoadCase for BeaconBlockBodyMerkleProofValidity<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let block_body: BeaconBlockBody<E, FullPayload<E>> = match fork_name {
            ForkName::Base | ForkName::Altair | ForkName::Bellatrix => {
                return Err(Error::InternalError(format!(
                    "Beacon block body merkle proof validity test skipped for {:?}",
                    fork_name
                )))
            }
            ForkName::Capella => {
                ssz_decode_file::<BeaconBlockBodyCapella<E>>(&path.join("object.ssz_snappy"))?
                    .into()
            }
            ForkName::Deneb => {
                ssz_decode_file::<BeaconBlockBodyDeneb<E>>(&path.join("object.ssz_snappy"))?.into()
            }
            ForkName::Electra => {
                ssz_decode_file::<BeaconBlockBodyElectra<E>>(&path.join("object.ssz_snappy"))?
                    .into()
            }
        };
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
            block_body,
            merkle_proof,
        })
    }
}

impl<E: EthSpec> Case for BeaconBlockBodyMerkleProofValidity<E> {
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let binding = self.block_body.clone();
        let block_body = binding.to_ref();
        let Ok(proof) = block_body.block_body_merkle_proof(self.merkle_proof.leaf_index) else {
            return Err(Error::FailedToParseTest(
                "Could not retrieve merkle proof".to_string(),
            ));
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

        Ok(())
    }
}
