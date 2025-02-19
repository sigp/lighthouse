use super::*;
use serde::Deserialize;
use std::marker::PhantomData;
use types::data_column_custody_group::{compute_columns_for_custody_group, CustodyIndex};

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct ComputeColumnsForCustodyGroups<E: EthSpec> {
    /// The custody group index.
    pub custody_group: CustodyIndex,
    /// The list of resulting custody columns.
    pub result: Vec<u64>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for ComputeColumnsForCustodyGroups<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("meta.yaml").as_path())
    }
}

impl<E: EthSpec> Case for ComputeColumnsForCustodyGroups<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name.fulu_enabled()
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let spec = E::default_spec();
        let computed_columns = compute_columns_for_custody_group(self.custody_group, &spec)
            .expect("should compute custody columns from group")
            .collect::<Vec<_>>();

        let expected = &self.result;
        if computed_columns == *expected {
            Ok(())
        } else {
            Err(Error::NotEqual(format!(
                "Got {computed_columns:?}\nExpected {expected:?}"
            )))
        }
    }
}
