use lighthouse_network::rpc::methods::DataColumnsByRootRequest;
use ssz_types::VariableList;
use std::sync::Arc;
use types::{
    ChainSpec, DataColumnSidecar, DataColumnsByRootIdentifier, EthSpec, ForkName, Hash256,
};

use super::{ActiveRequestItems, LookupVerifyError};

#[derive(Debug, Clone)]
pub struct DataColumnsByRootRequestParams {
    pub block_roots: Vec<Hash256>,
    pub indices: Vec<u64>,
}

impl DataColumnsByRootRequestParams {
    pub fn try_into_request<E: EthSpec>(
        self,
        fork_name: ForkName,
        spec: &ChainSpec,
    ) -> Result<DataColumnsByRootRequest<E>, &'static str> {
        let columns = VariableList::new(self.indices)
            .map_err(|_| "Number of indices exceeds total number of columns")?;
        let data_column_ids = self
            .block_roots
            .into_iter()
            .map(|block_root| DataColumnsByRootIdentifier {
                block_root,
                columns: columns.clone(),
            })
            .collect();
        DataColumnsByRootRequest::new(data_column_ids, spec.max_request_blocks(fork_name))
    }
}

pub struct DataColumnsByRootRequestItems<E: EthSpec> {
    request: DataColumnsByRootRequestParams,
    items: Vec<Arc<DataColumnSidecar<E>>>,
}

impl<E: EthSpec> DataColumnsByRootRequestItems<E> {
    pub fn new(request: DataColumnsByRootRequestParams) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for DataColumnsByRootRequestItems<E> {
    type Item = Arc<DataColumnSidecar<E>>;

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add(&mut self, data_column: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = data_column.block_root();
        if !self.request.block_roots.contains(&block_root) {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }

        if let DataColumnSidecar::Fulu(data_column) = data_column.as_ref()
            && !data_column.verify_inclusion_proof()
        {
            return Err(LookupVerifyError::InvalidInclusionProof);
        }

        if !self.request.indices.contains(data_column.index()) {
            return Err(LookupVerifyError::UnrequestedIndex(*data_column.index()));
        }
        if self
            .items
            .iter()
            .any(|d| d.block_root() == block_root && *d.index() == *data_column.index())
        {
            return Err(LookupVerifyError::DuplicatedData(
                data_column.slot(),
                *data_column.index(),
            ));
        }

        self.items.push(data_column);

        Ok(self.items.len() >= self.request.block_roots.len() * self.request.indices.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::test_utils::{NumBlobs, generate_rand_block_and_data_columns, test_spec};
    use types::{Epoch, ForkName, MinimalEthSpec as E};

    /// A response missing any requested `(block_root, index)` must not report the request complete,
    /// whether it covers all roots but misses an index, or all indices but misses a root.
    #[test]
    fn partial_response_does_not_complete() {
        // This test builds Fulu data columns, which is incompatible with a Gloas genesis.
        if test_spec::<E>()
            .fork_name_at_epoch(Epoch::new(0))
            .gloas_enabled()
        {
            return;
        }
        let mut spec = test_spec::<E>();
        spec.fulu_fork_epoch = Some(Epoch::new(0));
        let mut u = types::test_utils::test_unstructured();
        let a = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu,
            NumBlobs::Number(1),
            &mut u,
            &spec,
        )
        .unwrap()
        .1;
        let b = generate_rand_block_and_data_columns::<E>(
            ForkName::Fulu,
            NumBlobs::Number(1),
            &mut u,
            &spec,
        )
        .unwrap()
        .1;

        // Request columns [0, 1] for two block roots: 4 items expected.
        let params = DataColumnsByRootRequestParams {
            block_roots: vec![a[0].block_root(), b[0].block_root()],
            indices: vec![0, 1],
        };

        // All block roots, but index 1 missing.
        let mut items = DataColumnsByRootRequestItems::<E>::new(params.clone());
        assert_eq!(items.add(a[0].clone()), Ok(false));
        assert_eq!(items.add(b[0].clone()), Ok(false));

        // All indices, but block root `b` missing.
        let mut items = DataColumnsByRootRequestItems::<E>::new(params.clone());
        assert_eq!(items.add(a[0].clone()), Ok(false));
        assert_eq!(items.add(a[1].clone()), Ok(false));

        // The complete set resolves the request.
        let mut items = DataColumnsByRootRequestItems::<E>::new(params);
        assert_eq!(items.add(a[0].clone()), Ok(false));
        assert_eq!(items.add(a[1].clone()), Ok(false));
        assert_eq!(items.add(b[0].clone()), Ok(false));
        assert_eq!(items.add(b[1].clone()), Ok(true));
    }
}
