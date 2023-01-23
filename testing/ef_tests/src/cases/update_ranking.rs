use super::*;
use crate::case_result::compare_result_detailed;
use crate::decode::{ssz_decode_file_with, yaml_decode_file};
use compare_fields_derive::CompareFields;
use serde_derive::Deserialize;
use ssz::Decode;
use types::{EthSpec, ForkName, LightClientUpdate};

#[derive(Debug, Clone, Deserialize, CompareFields, PartialEq)]
struct BoolWrapper {
    wrapped_bool: bool,
}

impl BoolWrapper {
    fn new(b: bool) -> Self {
        Self { wrapped_bool: b }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub updates_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct UpdateRanking<E: EthSpec> {
    pub metadata: Metadata,
    pub updates: Vec<LightClientUpdate<E>>,
}

impl<E: EthSpec> LoadCase for UpdateRanking<E> {
    fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
        let metadata: Metadata = yaml_decode_file(&path.join("meta.yaml"))?;
        let updates = (0..metadata.updates_count)
            .map(|i| {
                let filename = format!("updates_{}.ssz_snappy", i);
                ssz_decode_file_with(&path.join(filename), |bytes| {
                    LightClientUpdate::from_ssz_bytes(&bytes)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { metadata, updates })
    }
}

impl<E: EthSpec> Case for UpdateRanking<E> {
    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let spec = &testing_spec::<E>(fork_name);
        let mut forward_bool = true;
        let mut rev_bool = false;

        self.updates.iter().enumerate().for_each(|(ind, update)| {
            self.updates.iter().skip(ind + 1).for_each(|other_update| {
                forward_bool &= update.is_better_update(other_update, spec);
                rev_bool |= other_update.is_better_update(update, spec);
            });
        });
        let forward_result: Result<BoolWrapper, Error> = Ok(BoolWrapper::new(forward_bool));
        let rev_result: Result<BoolWrapper, Error> = Ok(BoolWrapper::new(rev_bool));
        compare_result_detailed(&forward_result, &Some(BoolWrapper::new(true)))?;
        compare_result_detailed(&rev_result, &Some(BoolWrapper::new(false)))
    }
}
