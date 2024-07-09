use super::*;
use crate::case_result::compare_result;
use kzg::{CellsAndKzgProofs, KzgProof};
use serde::Deserialize;
use std::convert::Infallible;
use std::marker::PhantomData;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGRecoverCellsAndKzgProofsInput {
    pub cell_indices: Vec<u64>,
    pub cells: Vec<String>,
    pub proofs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct KZGRecoverCellsAndKZGProofs<E: EthSpec> {
    pub input: KZGRecoverCellsAndKzgProofsInput,
    pub output: Option<(Vec<String>, Vec<String>)>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for KZGRecoverCellsAndKZGProofs<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl<E: EthSpec> Case for KZGRecoverCellsAndKZGProofs<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name == ForkName::Deneb
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let parse_input = |input: &KZGRecoverCellsAndKzgProofsInput| {
            // Proofs are not used for `recover_cells_and_compute_kzg_proofs`, they are only checked
            // to satisfy the spec tests.
            if input.proofs.len() != input.cell_indices.len() {
                return Err(Error::SkippedKnownFailure);
            }

            let proofs = input
                .proofs
                .iter()
                .map(|s| parse_proof(s))
                .collect::<Result<Vec<_>, Error>>()?;

            let cells = input
                .cells
                .iter()
                .map(|s| parse_cell(s))
                .collect::<Result<Vec<_>, Error>>()?;

            Ok((proofs, cells, input.cell_indices.clone()))
        };

        let result =
            parse_input(&self.input).and_then(|(input_proofs, input_cells, cell_indices)| {
                let input_cells_ref: Vec<_> = input_cells.iter().map(|cell| &**cell).collect();
                let (cells, proofs) = KZG
                    .recover_cells_and_compute_kzg_proofs(
                        cell_indices.as_slice(),
                        input_cells_ref.as_slice(),
                    )
                    .map_err(|e| {
                        Error::InternalError(format!(
                            "Failed to recover cells and kzg proofs: {e:?}"
                        ))
                    })?;

                // Check recovered proofs matches inputs proofs. This is done only to satisfy the
                // spec tests, as the ckzg library recomputes all proofs and does not require
                // proofs to recover.
                for (input_proof, cell_id) in input_proofs.iter().zip(cell_indices) {
                    if let Err(e) = compare_result::<KzgProof, Infallible>(
                        &Ok(*input_proof),
                        &proofs.get(cell_id as usize).cloned(),
                    ) {
                        return Err(e);
                    }
                }

                Ok((cells, proofs))
            });

        let expected = self
            .output
            .as_ref()
            .and_then(|(cells, proofs)| parse_cells_and_proofs(cells, proofs).ok())
            .map(|(cells, proofs)| (cells.try_into().unwrap(), proofs.try_into().unwrap()));

        compare_result::<CellsAndKzgProofs, _>(&result, &expected)
    }
}
