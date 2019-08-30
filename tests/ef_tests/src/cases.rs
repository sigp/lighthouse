use super::*;
use std::fmt::Debug;
use std::path::Path;

mod bls_aggregate_pubkeys;
mod bls_aggregate_sigs;
mod bls_g2_compressed;
mod bls_g2_uncompressed;
mod bls_priv_to_pub;
mod bls_sign_msg;
mod epoch_processing;
mod genesis_initialization;
mod genesis_validity;
mod operations;
mod sanity_blocks;
mod sanity_slots;
mod shuffling;
mod ssz_generic;
mod ssz_static;

pub use bls_aggregate_pubkeys::*;
pub use bls_aggregate_sigs::*;
pub use bls_g2_compressed::*;
pub use bls_g2_uncompressed::*;
pub use bls_priv_to_pub::*;
pub use bls_sign_msg::*;
pub use epoch_processing::*;
pub use genesis_initialization::*;
pub use genesis_validity::*;
pub use operations::*;
pub use sanity_blocks::*;
pub use sanity_slots::*;
pub use shuffling::*;
pub use ssz_generic::*;
pub use ssz_static::*;

pub trait LoadCase: Sized {
    /// Load the test case from a test case directory.
    fn load_from_dir(_path: &Path) -> Result<Self, Error>;
}

pub trait Case: Debug {
    /// An optional field for implementing a custom description.
    ///
    /// Defaults to "no description".
    fn description(&self) -> String {
        "no description".to_string()
    }

    /// Path to the directory for this test case.
    fn path(&self) -> &Path {
        // FIXME(michael): remove default impl
        Path::new("")
    }

    /// Execute a test and return the result.
    ///
    /// `case_index` reports the index of the case in the set of test cases. It is not strictly
    /// necessary, but it's useful when troubleshooting specific failing tests.
    fn result(&self, case_index: usize) -> Result<(), Error>;
}

pub trait BlsCase: serde::de::DeserializeOwned {}

impl<T: BlsCase> YamlDecode for T {
    fn yaml_decode(string: &str) -> Result<Self, Error> {
        serde_yaml::from_str(string).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))
    }
}

impl<T: BlsCase> LoadCase for T {
    fn load_from_dir(path: &Path) -> Result<Self, Error> {
        Self::yaml_decode_file(&path.join("data.yaml"))
    }
}

#[derive(Debug)]
pub struct Cases<T> {
    pub test_cases: Vec<T>,
}

impl<T> EfTest for Cases<T>
where
    T: Case + Debug,
{
    fn test_results(&self) -> Vec<CaseResult> {
        self.test_cases
            .iter()
            .enumerate()
            .map(|(i, tc)| CaseResult::new(i, tc, tc.result(i)))
            .collect()
    }
}
