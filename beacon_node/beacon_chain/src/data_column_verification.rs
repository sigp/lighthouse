use derivative::Derivative;
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use types::data_column_sidecar::DataColumnSidecar;
use types::EthSpec;

/// Data column that we must custody and has completed kzg verification
#[derive(Debug, Derivative, Clone, Encode, Decode)]
#[derivative(PartialEq, Eq)]
#[ssz(struct_behaviour = "transparent")]
pub struct KzgVerifiedCustodyDataColumn<E: EthSpec> {
    data: Arc<DataColumnSidecar<E>>,
}
