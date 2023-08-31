use super::*;
use crate::case_result::compare_result;
use beacon_chain::kzg_utils::compute_kzg_proof;
use kzg::KzgProof;
use serde_derive::Deserialize;
use std::marker::PhantomData;
use std::str::FromStr;
use types::Hash256;

pub fn parse_point(point: &str) -> Result<Hash256, Error> {
    Hash256::from_str(&point[2..])
        .map_err(|e| Error::FailedToParseTest(format!("Failed to parse point: {:?}", e)))
}

#[derive(Debug, Clone, Deserialize)]
pub struct KZGComputeKZGProofInput {
    pub blob: String,
    pub z: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct KZGComputeKZGProof<E: EthSpec> {
    pub input: KZGComputeKZGProofInput,
    pub output: Option<(String, Hash256)>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for KZGComputeKZGProof<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl<E: EthSpec> Case for KZGComputeKZGProof<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Deneb
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let parse_input = |input: &KZGComputeKZGProofInput| -> Result<_, Error> {
            let blob = parse_blob::<E>(&input.blob)?;
            let z = parse_point(&input.z)?;
            Ok((blob, z))
        };

        let kzg = get_kzg::<E::Kzg>()?;
        let proof = parse_input(&self.input).and_then(|(blob, z)| {
            compute_kzg_proof::<E>(&kzg, &blob, z)
                .map_err(|e| Error::InternalError(format!("Failed to compute kzg proof: {:?}", e)))
        });

        let expected = self
            .output
            .as_ref()
            .and_then(|(s, z)| parse_proof(s).ok().map(|proof| (proof, *z)));

        compare_result::<(KzgProof, Hash256), _>(&proof, &expected)
    }
}
