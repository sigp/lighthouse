use super::*;
use alloy_primitives::U256;
use serde::Deserialize;
use std::marker::PhantomData;
use types::data_column_custody_group::{compute_columns_for_custody_group, get_custody_groups};

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct GetCustodyColumns<E: EthSpec> {
    /// The NodeID input.
    pub node_id: String,
    /// The count of custody groups.
    pub custody_group_count: u64,
    /// The list of resulting custody columns.
    pub result: Vec<u64>,
    #[serde(skip)]
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> LoadCase for GetCustodyColumns<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("meta.yaml").as_path())
    }
}

impl<E: EthSpec> Case for GetCustodyColumns<E> {
    fn is_enabled_for_fork(_fork_name: ForkName) -> bool {
        false
    }

    fn is_enabled_for_feature(feature_name: FeatureName) -> bool {
        feature_name == FeatureName::Fulu
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let spec = E::default_spec();
        let node_id = U256::from_str_radix(&self.node_id, 10)
            .map_err(|e| Error::FailedToParseTest(format!("{e:?}")))?;
        let raw_node_id = node_id.to_be_bytes::<32>();
        let computed_groups = get_custody_groups(raw_node_id, self.custody_group_count, &spec)
            .expect("should compute custody groups");

        let mut computed_columns = vec![];
        for custody_group in computed_groups {
            let columns = compute_columns_for_custody_group(custody_group, &spec)
                .expect("should compute custody columns from group");
            computed_columns.extend(columns);
        }
        // TODO: This test will be broken down into two separate tests in the next release and this
        // sort will not be needed.
        computed_columns.sort();

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
