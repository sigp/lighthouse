use super::*;
use crate::case_result::compare_result;
use beacon_chain::kzg_utils::blob_to_kzg_commitment;
use kzg::KzgCommitment;
use serde_derive::Deserialize;
use std::marker::PhantomData;

#[derive(Debug, Clone, Deserialize)]
pub struct KZGBlobToKZGCommitmentInput {
    pub blob: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct KZGBlobToKZGCommitment<E: EthSpec> {
    pub input: KZGBlobToKZGCommitmentInput,
    pub output: Option<String>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for KZGBlobToKZGCommitment<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl<E: EthSpec> Case for KZGBlobToKZGCommitment<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Deneb
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let kzg = get_kzg::<E::Kzg>()?;

        let commitment = parse_blob::<E>(&self.input.blob).and_then(|blob| {
            blob_to_kzg_commitment::<E>(&kzg, &blob).map_err(|e| {
                Error::InternalError(format!("Failed to compute kzg commitment: {:?}", e))
            })
        });

        let expected = self.output.as_ref().and_then(|s| parse_commitment(s).ok());

        compare_result::<KzgCommitment, _>(&commitment, &expected)
    }
}
