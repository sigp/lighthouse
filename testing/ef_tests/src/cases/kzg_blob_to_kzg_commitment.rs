use super::*;
use crate::case_result::compare_result;
use beacon_chain::kzg_utils::blob_to_kzg_commitment;
use kzg::KzgCommitment;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGBlobToKZGCommitmentInput {
    pub blob: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGBlobToKZGCommitment {
    pub input: KZGBlobToKZGCommitmentInput,
    pub output: Option<String>,
}

impl LoadCase for KZGBlobToKZGCommitment {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl Case for KZGBlobToKZGCommitment {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Deneb
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let kzg = get_kzg();
        let commitment = parse_blob(&self.input.blob).and_then(|blob| {
            blob_to_kzg_commitment(&kzg, &blob).map_err(|e| {
                Error::InternalError(format!("Failed to compute kzg commitment: {:?}", e))
            })
        });

        let expected = self.output.as_ref().and_then(|s| parse_commitment(s).ok());

        compare_result::<KzgCommitment, _>(&commitment, &expected)
    }
}
