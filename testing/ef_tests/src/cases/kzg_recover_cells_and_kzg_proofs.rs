use super::*;
use crate::case_result::compare_result;
use kzg::CellsAndKzgProofs;
use serde::Deserialize;
use std::marker::PhantomData;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGRecoverCellsAndKzgProofsInput {
    pub cell_indices: Vec<u64>,
    pub cells: Vec<String>,
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
            let cells = input
                .cells
                .iter()
                .map(|s| parse_cell(s))
                .collect::<Result<Vec<_>, Error>>()?;

            Ok((cells, input.cell_indices.clone()))
        };

        let result: Result<_, Error> =
            parse_input(&self.input).and_then(|(input_cells, cell_indices)| {
                let input_cells_ref: Vec<_> = input_cells.iter().map(|cell| &**cell).collect();
                let kzg = get_kzg();
                let (cells, proofs) = kzg
                    .recover_cells_and_compute_kzg_proofs(
                        cell_indices.as_slice(),
                        input_cells_ref.as_slice(),
                    )
                    .map_err(|e| {
                        Error::InternalError(format!(
                            "Failed to recover cells and kzg proofs: {e:?}"
                        ))
                    })?;

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
