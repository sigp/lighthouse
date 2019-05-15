use super::*;
use crate::yaml_decode::*;
use yaml_rust::YamlLoader;

mod ssz_generic;
mod ssz_static;

pub use ssz_generic::*;
pub use ssz_static::*;

#[derive(Debug, Deserialize)]
pub struct Cases<T> {
    pub test_cases: Vec<T>,
}

impl<T: YamlDecode> YamlDecode for Cases<T> {
    /// Decodes a YAML list of test cases
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        let doc = &YamlLoader::load_from_str(yaml).unwrap()[0];

        let mut test_cases: Vec<T> = vec![];

        let mut i = 0;
        loop {
            if doc[i].is_badvalue() {
                break;
            } else {
                test_cases.push(T::yaml_decode(&yaml_to_string(&doc[i])).unwrap())
            }

            i += 1;
        }

        Ok(Self { test_cases })
    }
}
