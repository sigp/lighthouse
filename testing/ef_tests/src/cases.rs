use super::*;
use rayon::prelude::*;
use std::fmt::{Debug, Display, Formatter};
use std::path::{Path, PathBuf};
use types::ForkName;

mod bls_aggregate_sigs;
mod bls_aggregate_verify;
mod bls_batch_verify;
mod bls_eth_aggregate_pubkeys;
mod bls_eth_fast_aggregate_verify;
mod bls_fast_aggregate_verify;
mod bls_sign_msg;
mod bls_verify_msg;
mod common;
mod epoch_processing;
mod fork;
mod fork_choice;
mod genesis_initialization;
mod genesis_validity;
mod get_custody_columns;
mod kzg_blob_to_kzg_commitment;
mod kzg_compute_blob_kzg_proof;
mod kzg_compute_cells_and_kzg_proofs;
mod kzg_compute_kzg_proof;
mod kzg_recover_cells_and_kzg_proofs;
mod kzg_verify_blob_kzg_proof;
mod kzg_verify_blob_kzg_proof_batch;
mod kzg_verify_cell_kzg_proof_batch;
mod kzg_verify_kzg_proof;
mod light_client_verify_is_better_update;
mod merkle_proof_validity;
mod operations;
mod rewards;
mod sanity_blocks;
mod sanity_slots;
mod shuffling;
mod ssz_generic;
mod ssz_static;
mod transition;

pub use self::fork_choice::*;
pub use bls_aggregate_sigs::*;
pub use bls_aggregate_verify::*;
pub use bls_batch_verify::*;
pub use bls_eth_aggregate_pubkeys::*;
pub use bls_eth_fast_aggregate_verify::*;
pub use bls_fast_aggregate_verify::*;
pub use bls_sign_msg::*;
pub use bls_verify_msg::*;
pub use common::SszStaticType;
pub use epoch_processing::*;
pub use fork::ForkTest;
pub use genesis_initialization::*;
pub use genesis_validity::*;
pub use get_custody_columns::*;
pub use kzg_blob_to_kzg_commitment::*;
pub use kzg_compute_blob_kzg_proof::*;
pub use kzg_compute_cells_and_kzg_proofs::*;
pub use kzg_compute_kzg_proof::*;
pub use kzg_recover_cells_and_kzg_proofs::*;
pub use kzg_verify_blob_kzg_proof::*;
pub use kzg_verify_blob_kzg_proof_batch::*;
pub use kzg_verify_cell_kzg_proof_batch::*;
pub use kzg_verify_kzg_proof::*;
pub use light_client_verify_is_better_update::*;
pub use merkle_proof_validity::*;
pub use operations::*;
pub use rewards::RewardsTest;
pub use sanity_blocks::*;
pub use sanity_slots::*;
pub use shuffling::*;
pub use ssz_generic::*;
pub use ssz_static::*;
pub use transition::TransitionTest;

#[derive(Debug, PartialEq)]
pub enum FeatureName {
    Eip7594,
}

impl Display for FeatureName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FeatureName::Eip7594 => f.write_str("eip7594"),
        }
    }
}

pub trait LoadCase: Sized {
    /// Load the test case from a test case directory.
    fn load_from_dir(_path: &Path, _fork_name: ForkName) -> Result<Self, Error>;
}

pub trait Case: Debug + Sync {
    /// An optional field for implementing a custom description.
    ///
    /// Defaults to "no description".
    fn description(&self) -> String {
        "no description".to_string()
    }

    /// Whether or not this test exists for the given `fork_name`.
    ///
    /// Returns `true` by default.
    fn is_enabled_for_fork(_fork_name: ForkName) -> bool {
        true
    }

    /// Whether or not this test exists for the given `feature_name`.
    ///
    /// Returns `true` by default.
    fn is_enabled_for_feature(_feature_name: FeatureName) -> bool {
        true
    }

    /// Execute a test and return the result.
    ///
    /// `case_index` reports the index of the case in the set of test cases. It is not strictly
    /// necessary, but it's useful when troubleshooting specific failing tests.
    fn result(&self, case_index: usize, fork_name: ForkName) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct Cases<T> {
    pub test_cases: Vec<(PathBuf, T)>,
}

impl<T: Case> Cases<T> {
    pub fn test_results(&self, fork_name: ForkName, use_rayon: bool) -> Vec<CaseResult> {
        if use_rayon {
            self.test_cases
                .into_par_iter()
                .enumerate()
                .map(|(i, (ref path, ref tc))| {
                    CaseResult::new(i, path, tc, tc.result(i, fork_name))
                })
                .collect()
        } else {
            self.test_cases
                .iter()
                .enumerate()
                .map(|(i, (ref path, ref tc))| {
                    CaseResult::new(i, path, tc, tc.result(i, fork_name))
                })
                .collect()
        }
    }
}
