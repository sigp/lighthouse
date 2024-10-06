use super::{ActiveRequestItems, LookupVerifyError};
use lighthouse_network::rpc::methods::DataColumnsByRangeRequest;
use std::sync::Arc;
use types::{DataColumnSidecar, EthSpec};

/// Accumulates results of a data_columns_by_range request. Only returns items after receiving the
/// stream termination.
pub struct DataColumnsByRangeRequestItems<E: EthSpec> {
    request: DataColumnsByRangeRequest,
    items: Vec<Arc<DataColumnSidecar<E>>>,
}

impl<E: EthSpec> DataColumnsByRangeRequestItems<E> {
    pub fn new(request: DataColumnsByRangeRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for DataColumnsByRangeRequestItems<E> {
    type Item = Arc<DataColumnSidecar<E>>;

    fn add(&mut self, item: Self::Item) -> Result<bool, LookupVerifyError> {
        if item.slot() < self.request.start_slot
            || item.slot() >= self.request.start_slot + self.request.count
        {
            return Err(LookupVerifyError::UnrequestedSlot(item.slot()));
        }
        if !self.request.columns.contains(&item.index) {
            return Err(LookupVerifyError::UnrequestedIndex(item.index));
        }

        self.items.push(item);

        Ok(self.items.len() >= self.request.count as usize * self.request.columns.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
