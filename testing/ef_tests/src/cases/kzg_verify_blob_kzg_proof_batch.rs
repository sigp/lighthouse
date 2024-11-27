use super::*;
use crate::case_result::compare_result;
use beacon_chain::kzg_utils::validate_blobs;
use kzg::Error as KzgError;
use serde::Deserialize;
use std::marker::PhantomData;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGVerifyBlobKZGProofBatchInput {
    pub blobs: Vec<String>,
    pub commitments: Vec<String>,
    pub proofs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct KZGVerifyBlobKZGProofBatch<E: EthSpec> {
    pub input: KZGVerifyBlobKZGProofBatchInput,
    pub output: Option<bool>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for KZGVerifyBlobKZGProofBatch<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl<E: EthSpec> Case for KZGVerifyBlobKZGProofBatch<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Deneb
    }

    fn is_enabled_for_feature(feature_name: FeatureName) -> bool {
        feature_name != FeatureName::Eip7594
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let parse_input = |input: &KZGVerifyBlobKZGProofBatchInput| -> Result<_, Error> {
            let blobs = input
                .blobs
                .iter()
                .map(|s| parse_blob::<E>(s))
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
            parse_input(&self.input).and_then(
                |(commitments, blobs, proofs)| match validate_blobs::<E>(
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
                },
            );

        compare_result::<bool, _>(&result, &self.output)
    }
}
