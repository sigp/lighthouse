use super::*;
use crate::case_result::compare_result;
use beacon_chain::kzg_utils::validate_blob;
use eth2_network_config::TRUSTED_SETUP;
use kzg::{Kzg, KzgCommitment, KzgProof, TrustedSetup};
use serde_derive::Deserialize;
use std::convert::TryInto;
use std::marker::PhantomData;
use types::Blob;

pub fn get_kzg() -> Result<Kzg, Error> {
    let trusted_setup: TrustedSetup = serde_json::from_reader(TRUSTED_SETUP)
        .map_err(|e| Error::InternalError(format!("Failed to initialize kzg: {:?}", e)))?;
    Kzg::new_from_trusted_setup(trusted_setup)
        .map_err(|e| Error::InternalError(format!("Failed to initialize kzg: {:?}", e)))
}

pub fn parse_proof(proof: &str) -> Result<KzgProof, Error> {
    hex::decode(&proof[2..])
        .map_err(|e| Error::FailedToParseTest(format!("Failed to parse proof: {:?}", e)))
        .and_then(|bytes| {
            bytes
                .try_into()
                .map_err(|e| Error::FailedToParseTest(format!("Failed to parse proof: {:?}", e)))
        })
        .map(KzgProof)
}

pub fn parse_commitment(commitment: &str) -> Result<KzgCommitment, Error> {
    hex::decode(&commitment[2..])
        .map_err(|e| Error::FailedToParseTest(format!("Failed to parse commitment: {:?}", e)))
        .and_then(|bytes| {
            bytes.try_into().map_err(|e| {
                Error::FailedToParseTest(format!("Failed to parse commitment: {:?}", e))
            })
        })
        .map(KzgCommitment)
}

pub fn parse_blob(blob: &str) -> Result<Blob, Error> {
    hex::decode(&blob[2..])
        .map_err(|e| Error::FailedToParseTest(format!("Failed to parse blob: {:?}", e)))
        .and_then(|bytes| {
            Blob::try_from(bytes)
                .map_err(|e| Error::FailedToParseTest(format!("Failed to parse blob: {:?}", e)))
        })
}

#[derive(Debug, Clone, Deserialize)]
pub struct KZGVerifyBlobKZGProofInput {
    pub blob: String,
    pub commitment: String,
    pub proof: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct KZGVerifyBlobKZGProof<E: EthSpec> {
    pub input: KZGVerifyBlobKZGProofInput,
    pub output: Option<bool>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for KZGVerifyBlobKZGProof<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl<E: EthSpec> Case for KZGVerifyBlobKZGProof<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Deneb
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let parse_input =
            |input: &KZGVerifyBlobKZGProofInput| -> Result<(Blob, KzgCommitment, KzgProof), Error> {
                let blob = parse_blob(&input.blob)?;
                let commitment = parse_commitment(&input.commitment)?;
                let proof = parse_proof(&input.proof)?;
                Ok((blob, commitment, proof))
            };

        let kzg = get_kzg()?;
        let result = parse_input(&self.input).and_then(|(blob, commitment, proof)| {
            validate_blob(&kzg, &blob, commitment, proof)
                .map_err(|e| Error::InternalError(format!("Failed to validate blob: {:?}", e)))
        });

        compare_result::<bool, _>(&result, &self.output)
    }
}
