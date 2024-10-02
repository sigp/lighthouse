use super::*;
use crate::case_result::compare_result;
use beacon_chain::kzg_utils::validate_blob;
use kzg::trusted_setup::get_trusted_setup;
use kzg::{Cell, Error as KzgError, Kzg, KzgCommitment, KzgProof, TrustedSetup};
use serde::Deserialize;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::LazyLock;
use types::Blob;

static KZG: LazyLock<Arc<Kzg>> = LazyLock::new(|| {
    let trusted_setup: TrustedSetup = serde_json::from_reader(get_trusted_setup().as_slice())
        .map_err(|e| Error::InternalError(format!("Failed to initialize trusted setup: {:?}", e)))
        .expect("failed to initialize trusted setup");
    let kzg = Kzg::new_from_trusted_setup_das_enabled(trusted_setup)
        .map_err(|e| Error::InternalError(format!("Failed to initialize kzg: {:?}", e)))
        .expect("failed to initialize kzg");
    Arc::new(kzg)
});

pub fn get_kzg() -> Arc<Kzg> {
    Arc::clone(&KZG)
}

pub fn parse_cells_and_proofs(
    cells: &[String],
    proofs: &[String],
) -> Result<(Vec<Cell>, Vec<KzgProof>), Error> {
    let cells = cells
        .iter()
        .map(|s| parse_cell(s.as_str()))
        .collect::<Result<Vec<_>, Error>>()?;

    let proofs = proofs
        .iter()
        .map(|s| parse_proof(s.as_str()))
        .collect::<Result<Vec<_>, Error>>()?;

    Ok((cells, proofs))
}

pub fn parse_cell(cell: &str) -> Result<Cell, Error> {
    hex::decode(strip_0x(cell)?)
        .map_err(|e| Error::FailedToParseTest(format!("Failed to parse cell: {:?}", e)))
        .and_then(|bytes| {
            bytes
                .try_into()
                .map_err(|e| Error::FailedToParseTest(format!("Failed to parse cell: {:?}", e)))
        })
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

    fn is_enabled_for_feature(feature_name: FeatureName) -> bool {
        feature_name != FeatureName::Eip7594
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let parse_input = |input: &KZGVerifyBlobKZGProofInput| -> Result<(Blob<E>, KzgCommitment, KzgProof), Error> {
            let blob = parse_blob::<E>(&input.blob)?;
            let commitment = parse_commitment(&input.commitment)?;
            let proof = parse_proof(&input.proof)?;
            Ok((blob, commitment, proof))
        };

        let kzg = get_kzg();
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
