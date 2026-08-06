use super::*;
use crate::case_result::compare_result;
use beacon_chain::kzg_utils::verify_kzg_proof;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGVerifyKZGProofInput {
    pub commitment: String,
    pub z: String,
    pub y: String,
    pub proof: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGVerifyKZGProof {
    pub input: KZGVerifyKZGProofInput,
    pub output: Option<bool>,
}

impl LoadCase for KZGVerifyKZGProof {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl Case for KZGVerifyKZGProof {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Deneb
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
            verify_kzg_proof(&kzg, commitment, proof, z, y)
                .map_err(|e| Error::InternalError(format!("Failed to validate proof: {:?}", e)))
        });

        compare_result::<bool, _>(&result, &self.output)
    }
}
