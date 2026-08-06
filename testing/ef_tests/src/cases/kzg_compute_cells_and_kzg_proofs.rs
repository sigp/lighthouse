use super::*;
use crate::case_result::compare_result;
use kzg::CellsAndKzgProofs;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGComputeCellsAndKzgProofsInput {
    pub blob: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KZGComputeCellsAndKZGProofs {
    pub input: KZGComputeCellsAndKzgProofsInput,
    pub output: Option<(Vec<String>, Vec<String>)>,
}

impl LoadCase for KZGComputeCellsAndKZGProofs {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("data.yaml").as_path())
    }
}

impl Case for KZGComputeCellsAndKZGProofs {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name.fulu_enabled()
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let cells_and_proofs = parse_blob(&self.input.blob).and_then(|blob| {
            let blob = blob.as_ref().try_into().map_err(|e| {
                Error::InternalError(format!("Failed to convert blob to kzg blob: {e:?}"))
            })?;
            let kzg = get_kzg();
            kzg.compute_cells_and_proofs(blob).map_err(|e| {
                Error::InternalError(format!("Failed to compute cells and kzg proofs: {e:?}"))
            })
        });

        let expected = self.output.as_ref().and_then(|(cells, proofs)| {
            parse_cells_and_proofs(cells, proofs)
                .map(|(cells, proofs)| {
                    (
                        cells
                            .try_into()
                            .map_err(|e| {
                                Error::FailedToParseTest(format!("Failed to parse cells: {e:?}"))
                            })
                            .unwrap(),
                        proofs
                            .try_into()
                            .map_err(|e| {
                                Error::FailedToParseTest(format!("Failed to parse proofs: {e:?}"))
                            })
                            .unwrap(),
                    )
                })
                .ok()
        });

        compare_result::<CellsAndKzgProofs, _>(&cells_and_proofs, &expected)
    }
}
