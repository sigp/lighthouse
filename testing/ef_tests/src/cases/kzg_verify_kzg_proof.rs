use super::*;
use crate::case_result::compare_result;
use beacon_chain::kzg_utils::verify_kzg_proof;
use serde::Deserialize;
use std::marker::PhantomData;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGVerifyKZGProofInput {
    pub commitment: String,
    pub z: String,
    pub y: String,
    pub proof: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct KZGVerifyKZGProof<E: EthSpec> {
    pub input: KZGVerifyKZGProofInput,
    pub output: Option<bool>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for KZGVerifyKZGProof<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl<E: EthSpec> Case for KZGVerifyKZGProof<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Deneb
    }

    fn is_enabled_for_feature(feature_name: FeatureName) -> bool {
        feature_name != FeatureName::Eip7594
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let parse_input = |input: &KZGVerifyKZGProofInput| -> Result<_, Error> {
            let commitment = parse_commitment(&input.commitment)?;
            let z = parse_point(&input.z)?;
            let y = parse_point(&input.y)?;
            let proof = parse_proof(&input.proof)?;
            Ok((commitment, z, y, proof))
        };

        let kzg = get_kzg();
        let result = parse_input(&self.input).and_then(|(commitment, z, y, proof)| {
            verify_kzg_proof::<E>(&kzg, commitment, proof, z, y)
                .map_err(|e| Error::InternalError(format!("Failed to validate proof: {:?}", e)))
        });

        compare_result::<bool, _>(&result, &self.output)
    }
}
