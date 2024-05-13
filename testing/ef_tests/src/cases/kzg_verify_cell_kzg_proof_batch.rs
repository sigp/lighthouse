use super::*;
use crate::case_result::compare_result;
use kzg::{Bytes48, Error as KzgError};
use serde::Deserialize;
use std::marker::PhantomData;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGVerifyCellKZGProofBatchInput {
    pub row_commitments: Vec<String>,
    pub row_indices: Vec<usize>,
    pub column_indices: Vec<usize>,
    pub cells: Vec<String>,
    pub proofs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct KZGVerifyCellKZGProofBatch<E: EthSpec> {
    pub input: KZGVerifyCellKZGProofBatchInput,
    pub output: Option<bool>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for KZGVerifyCellKZGProofBatch<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl<E: EthSpec> Case for KZGVerifyCellKZGProofBatch<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Deneb
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let parse_input = |input: &KZGVerifyCellKZGProofBatchInput| -> Result<_, Error> {
            let (cells, proofs) = parse_cells_and_proofs(&input.cells, &input.proofs)?;
            let row_commitments = input
                .row_commitments
                .iter()
                .map(|s| parse_commitment(s))
                .collect::<Result<Vec<_>, _>>()?;
            let coordinates = input
                .row_indices
                .iter()
                .zip(&input.column_indices)
                .map(|(&row, &col)| (row as u64, col as u64))
                .collect::<Vec<_>>();

            Ok((cells, proofs, coordinates, row_commitments))
        };

        let result =
            parse_input(&self.input).and_then(|(cells, proofs, coordinates, commitments)| {
                let proofs: Vec<Bytes48> = proofs.iter().map(|&proof| proof.into()).collect();
                let commitments: Vec<Bytes48> = commitments.iter().map(|&c| c.into()).collect();
                match KZG.verify_cell_proof_batch(
                    cells.as_slice(),
                    &proofs,
                    &coordinates,
                    &commitments,
                ) {
                    Ok(_) => Ok(true),
                    Err(KzgError::KzgVerificationFailed) => Ok(false),
                    Err(e) => Err(Error::InternalError(format!(
                        "Failed to validate cells: {:?}",
                        e
                    ))),
                }
            });

        compare_result::<bool, _>(&result, &self.output)
    }
}
