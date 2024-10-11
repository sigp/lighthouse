use strum::IntoStaticStr;
use types::Hash256;

pub use blobs_by_root::{ActiveBlobsByRootRequest, BlobsByRootSingleBlockRequest};
pub use blocks_by_root::{ActiveBlocksByRootRequest, BlocksByRootSingleRequest};
pub use data_columns_by_root::{
    ActiveDataColumnsByRootRequest, DataColumnsByRootSingleBlockRequest,
};

mod blobs_by_root;
mod blocks_by_root;
mod data_columns_by_root;

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupVerifyError {
    NoResponseReturned,
    NotEnoughResponsesReturned { expected: usize, actual: usize },
    TooManyResponses,
    UnrequestedBlockRoot(Hash256),
    UnrequestedIndex(u64),
    InvalidInclusionProof,
    DuplicateData,
}
