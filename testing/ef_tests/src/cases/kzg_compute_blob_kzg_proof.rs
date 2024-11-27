use super::*;
use crate::case_result::compare_result;
use beacon_chain::kzg_utils::compute_blob_kzg_proof;
use kzg::KzgProof;
use serde::Deserialize;
use std::marker::PhantomData;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGComputeBlobKZGProofInput {
    pub blob: String,
    pub commitment: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct KZGComputeBlobKZGProof<E: EthSpec> {
    pub input: KZGComputeBlobKZGProofInput,
    pub output: Option<String>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for KZGComputeBlobKZGProof<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl<E: EthSpec> Case for KZGComputeBlobKZGProof<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Deneb
    }

    fn is_enabled_for_feature(feature_name: FeatureName) -> bool {
        feature_name != FeatureName::Eip7594
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let parse_input = |input: &KZGComputeBlobKZGProofInput| -> Result<_, Error> {
            let blob = parse_blob::<E>(&input.blob)?;
            let commitment = parse_commitment(&input.commitment)?;
            Ok((blob, commitment))
        };

        let kzg = get_kzg();
        let proof = parse_input(&self.input).and_then(|(blob, commitment)| {
            compute_blob_kzg_proof::<E>(&kzg, &blob, commitment)
                .map_err(|e| Error::InternalError(format!("Failed to compute kzg proof: {:?}", e)))
        });

        let expected = self.output.as_ref().and_then(|s| parse_proof(s).ok());

        compare_result::<KzgProof, _>(&proof, &expected)
    }
}
