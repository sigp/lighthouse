use super::*;
use alloy_primitives::U256;
use serde::Deserialize;
use types::data::get_custody_groups;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetCustodyGroups {
    /// The NodeID input.
    pub node_id: String,
    /// The count of custody groups.
    pub custody_group_count: u64,
    /// The list of resulting custody groups.
    pub result: Vec<u64>,
}

impl LoadCase for GetCustodyGroups {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        decode::yaml_decode_file(path.join("meta.yaml").as_path())
    }
}

impl Case for GetCustodyGroups {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        fork_name.fulu_enabled()
    }

    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let spec = Spec::default_spec();
        let node_id = U256::from_str_radix(&self.node_id, 10)
            .map_err(|e| Error::FailedToParseTest(format!("{e:?}")))?;
        let raw_node_id = node_id.to_be_bytes::<32>();
        let mut computed = get_custody_groups(raw_node_id, self.custody_group_count, &spec)
            .map(|set| set.into_iter().collect::<Vec<_>>())
            .expect("should compute custody groups");
        computed.sort();

        let expected = &self.result;
        if computed == *expected {
            Ok(())
        } else {
            Err(Error::NotEqual(format!(
                "Got {computed:?}\nExpected {expected:?}"
            )))
        }
    }
}
