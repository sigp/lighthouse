use super::*;
use serde::Deserialize;
use types::data::{CustodyIndex, compute_columns_for_custody_group};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeColumnsForCustodyGroups {
    /// The custody group index.
    pub custody_group: CustodyIndex,
    /// The list of resulting custody columns.
    pub result: Vec<u64>,
}

impl LoadCase for ComputeColumnsForCustodyGroups {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("meta.yaml").as_path())
    }
}

impl Case for ComputeColumnsForCustodyGroups {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name.fulu_enabled()
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let spec = Spec::default_spec();
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
