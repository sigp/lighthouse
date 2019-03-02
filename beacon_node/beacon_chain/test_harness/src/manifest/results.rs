use super::yaml_helpers::{as_usize, as_vec_u64};
use yaml_rust::Yaml;

pub struct Results {
    pub num_validators: Option<usize>,
    pub slashed_validators: Option<Vec<u64>>,
    pub exited_validators: Option<Vec<u64>>,
}

impl Results {
    pub fn from_yaml(yaml: &Yaml) -> Self {
        Self {
            num_validators: as_usize(&yaml, "num_validators"),
            slashed_validators: as_vec_u64(&yaml, "slashed_validators"),
            exited_validators: as_vec_u64(&yaml, "exited_validators"),
        }
    }
}
