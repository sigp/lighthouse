use super::*;
use crate::case_result::compare_result;
use beacon_chain::kzg_utils::validate_blob;
use eth2_network_config::TRUSTED_SETUP_BYTES;
use kzg::{Error as KzgError, Kzg, KzgCommitment, KzgProof, TrustedSetup};
use serde::Deserialize;
use std::marker::PhantomData;
use types::Blob;

pub fn get_kzg() -> Result<Kzg, Error> {
    let trusted_setup: TrustedSetup = serde_json::from_reader(TRUSTED_SETUP_BYTES)
        .map_err(|e| Error::InternalError(format!("Failed to initialize kzg: {:?}", e)))?;
    Kzg::new_from_trusted_setup(trusted_setup)
        .map_err(|e| Error::InternalError(format!("Failed to initialize kzg: {:?}", e)))
}

pub fn parse_proof(proof: &str) -> Result<KzgProof, Error> {
    hex::decode(strip_0x(proof)?)
        .map_err(|e| Error::FailedToParseTest(format!("Failed to parse proof: {:?}", e)))
        .and_then(|bytes| {
            bytes
                .try_into()
                .map_err(|e| Error::FailedToParseTest(format!("Failed to parse proof: {:?}", e)))
        })
        .map(KzgProof)
}

pub fn parse_commitment(commitment: &str) -> Result<KzgCommitment, Error> {
    hex::decode(strip_0x(commitment)?)
        .map_err(|e| Error::FailedToParseTest(format!("Failed to parse commitment: {:?}", e)))
        .and_then(|bytes| {
            bytes.try_into().map_err(|e| {
                Error::FailedToParseTest(format!("Failed to parse commitment: {:?}", e))
            })
        })
        .map(KzgCommitment)
}

pub fn parse_blob<E: EthSpec>(blob: &str) -> Result<Blob<E>, Error> {
    hex::decode(strip_0x(blob)?)
        .map_err(|e| Error::FailedToParseTest(format!("Failed to parse blob: {:?}", e)))
        .and_then(|bytes| {
            Blob::<E>::new(bytes)
                .map_err(|e| Error::FailedToParseTest(format!("Failed to parse blob: {:?}", e)))
        })
}

fn strip_0x(s: &str) -> Result<&str, Error> {
    s.strip_prefix("0x").ok_or(Error::FailedToParseTest(format!(
        "Hex is missing 0x prefix: {}",
        s
    )))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGVerifyBlobKZGProofInput {
    pub blob: String,
    pub commitment: String,
    pub proof: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
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
        let parse_input = |input: &KZGVerifyBlobKZGProofInput| -> Result<(Blob<E>, KzgCommitment, KzgProof), Error> {
            let blob = parse_blob::<E>(&input.blob)?;
            let commitment = parse_commitment(&input.commitment)?;
            let proof = parse_proof(&input.proof)?;
            Ok((blob, commitment, proof))
        };

        let kzg = get_kzg()?;
        let result = parse_input(&self.input).and_then(|(blob, commitment, proof)| {
            match validate_blob::<E>(&kzg, &blob, commitment, proof) {
                Ok(_) => Ok(true),
                Err(KzgError::KzgVerificationFailed) => Ok(false),
                Err(e) => Err(Error::InternalError(format!(
                    "Failed to validate blob: {:?}",
                    e
                ))),
            }
        });

        compare_result::<bool, _>(&result, &self.output)
    }
}
