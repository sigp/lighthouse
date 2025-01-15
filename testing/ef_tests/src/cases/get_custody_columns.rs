use super::*;
use alloy_primitives::U256;
use serde::Deserialize;
use std::marker::PhantomData;
use types::DataColumnSubnetId;

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
pub struct GetCustodyColumns<E: EthSpec> {
    pub node_id: String,
    pub custody_subnet_count: u64,
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
    fn result(&self, _case_index: usize, _fork_name: ForkName) -> Result<(), Error> {
        let spec = E::default_spec();
        let node_id = U256::from_str_radix(&self.node_id, 10)
            .map_err(|e| Error::FailedToParseTest(format!("{e:?}")))?;
        let raw_node_id = node_id.to_be_bytes::<32>();
        let computed = DataColumnSubnetId::compute_custody_columns::<E>(
            raw_node_id,
            self.custody_subnet_count,
            &spec,
        )
        .expect("should compute custody columns")
        .collect::<Vec<_>>();
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
