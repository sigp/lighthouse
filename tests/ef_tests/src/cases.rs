use super::*;
use crate::yaml_decode::*;
use yaml_rust::YamlLoader;

mod bls_aggregate_pubkeys;
mod bls_aggregate_sigs;
mod bls_g2_compressed;
mod bls_g2_uncompressed;
mod bls_priv_to_pub;
mod bls_sign_msg;
mod ssz_generic;
mod ssz_static;

pub use bls_aggregate_pubkeys::*;
pub use bls_aggregate_sigs::*;
pub use bls_g2_compressed::*;
pub use bls_g2_uncompressed::*;
pub use bls_priv_to_pub::*;
pub use bls_sign_msg::*;
pub use ssz_generic::*;
pub use ssz_static::*;

#[derive(Debug)]
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
            // `is_badvalue` indicates when we have reached the end of the YAML list.
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
