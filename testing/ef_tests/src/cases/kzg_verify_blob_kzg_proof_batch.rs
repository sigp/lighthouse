use super::*;
use crate::case_result::compare_result;
use beacon_chain::kzg_utils::validate_blobs;
use kzg::Error as KzgError;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGVerifyBlobKZGProofBatchInput {
    pub blobs: Vec<String>,
    pub commitments: Vec<String>,
    pub proofs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGVerifyBlobKZGProofBatch {
    pub input: KZGVerifyBlobKZGProofBatchInput,
    pub output: Option<bool>,
}

impl LoadCase for KZGVerifyBlobKZGProofBatch {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl Case for KZGVerifyBlobKZGProofBatch {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Deneb
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let parse_input = |input: &KZGVerifyBlobKZGProofBatchInput| -> Result<_, Error> {
            let blobs = input
                .blobs
                .iter()
                .map(|s| parse_blob(s))
                .collect::<Result<Vec<_>, _>>()?;
            let commitments = input
                .commitments
                .iter()
                .map(|s| parse_commitment(s))
                .collect::<Result<Vec<_>, _>>()?;
            let proofs = input
                .proofs
                .iter()
                .map(|s| parse_proof(s))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((commitments, blobs, proofs))
        };

        let kzg = get_kzg();
        let result =
            parse_input(&self.input).and_then(|(commitments, blobs, proofs)| match validate_blobs(
                &kzg,
                &commitments,
                blobs.iter().collect(),
                &proofs,
            ) {
                Ok(_) => Ok(true),
                Err(KzgError::KzgVerificationFailed) => Ok(false),
                Err(e) => Err(Error::InternalError(format!(
                    "Failed to validate blobs: {:?}",
                    e
                ))),
            });

        compare_result::<bool, _>(&result, &self.output)
    }
}
