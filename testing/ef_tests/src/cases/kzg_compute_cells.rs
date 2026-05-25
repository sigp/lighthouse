use super::*;
use crate::case_result::compare_result;
use kzg::Cell;
use serde::Deserialize;
use std::marker::PhantomData;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGComputeCellsInput {
    pub blob: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct KZGComputeCells<E: EthSpec> {
    pub input: KZGComputeCellsInput,
    pub output: Option<Vec<String>>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for KZGComputeCells<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl<E: EthSpec> Case for KZGComputeCells<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name.fulu_enabled()
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let cells = parse_blob::<E>(&self.input.blob)
            .and_then(|blob| {
                let blob = blob.as_ref().try_into().map_err(|e| {
                    Error::InternalError(format!("Failed to convert blob to kzg blob: {e:?}"))
                })?;
                let kzg = get_kzg();
                kzg.compute_cells(blob).map_err(|e| {
                    Error::InternalError(format!("Failed to compute cells and kzg proofs: {e:?}"))
                })
            })
            .map(|cells| cells.to_vec());

        let expected = self.output.as_ref().map(|cells| {
            parse_cells_and_proofs(cells, &[])
                .map(|(cells, _)| cells)
                .expect("Valid cells")
        });

        compare_result::<Vec<Cell>, _>(&cells, &expected)
    }
}
