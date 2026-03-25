pub mod consts;

pub use kzg::{Error as KzgError, Kzg, KzgCommitment, KzgProof};

use ssz_types::VariableList;

use crate::core::EthSpec;

// Note on List limit:
// - Deneb to Electra: `MaxBlobCommitmentsPerBlock`
// - Fulu: `MaxCellsPerBlock`
// We choose to use a single type (with the larger value from Fulu as `N`) instead of having to
// introduce a new type for Fulu. This is to avoid messy conversions and having to add extra types
// with no gains - as `N` does not impact serialisation at all, and only affects merkleization,
// which we don't current do on `KzgProofs` anyway.
pub type KzgProofs<E> = VariableList<KzgProof, <E as EthSpec>::MaxCellsPerBlock>;

pub type KzgCommitments<E> =
    VariableList<KzgCommitment, <E as EthSpec>::MaxBlobCommitmentsPerBlock>;

/// Util method helpful for logging.
pub fn format_kzg_commitments(commitments: &[KzgCommitment]) -> String {
    let commitment_strings: Vec<String> = commitments.iter().map(|x| x.to_string()).collect();
    let commitments_joined = commitment_strings.join(", ");
    let surrounded_commitments = format!("[{}]", commitments_joined);
    surrounded_commitments
}
