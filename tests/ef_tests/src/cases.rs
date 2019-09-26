use super::*;
use rayon::prelude::*;
use std::fmt::Debug;
use std::path::{Path, PathBuf};

mod bls_aggregate_pubkeys;
mod bls_aggregate_sigs;
mod bls_g2_compressed;
mod bls_g2_uncompressed;
mod bls_priv_to_pub;
mod bls_sign_msg;
mod common;
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
pub use common::SszStaticType;
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

pub trait Case: Debug + Sync {
    /// An optional field for implementing a custom description.
    ///
    /// Defaults to "no description".
    fn description(&self) -> String {
        "no description".to_string()
    }

    /// Execute a test and return the result.
    ///
    /// `case_index` reports the index of the case in the set of test cases. It is not strictly
    /// necessary, but it's useful when troubleshooting specific failing tests.
    fn result(&self, case_index: usize) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct Cases<T> {
    pub test_cases: Vec<(PathBuf, T)>,
}

impl<T: Case> Cases<T> {
    pub fn test_results(&self) -> Vec<CaseResult> {
        self.test_cases
            .into_par_iter()
            .enumerate()
            .map(|(i, (ref path, ref tc))| CaseResult::new(i, path, tc, tc.result(i)))
            .collect()
    }
}
