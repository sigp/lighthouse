use super::{ActiveRequestItems, LookupVerifyError};
use lighthouse_network::rpc::methods::DataColumnsByRangeRequest;
use std::{cmp::Ordering, sync::Arc};
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

    fn add(&mut self, data_column: Self::Item) -> Result<bool, LookupVerifyError> {
        if data_column.slot() < self.request.start_slot
            || data_column.slot() >= self.request.start_slot + self.request.count
        {
            return Err(LookupVerifyError::UnrequestedSlot(data_column.slot()));
        }
        if !self.request.columns.contains(&data_column.index) {
            return Err(LookupVerifyError::UnrequestedIndex(data_column.index));
        }
        if !data_column.verify_inclusion_proof() {
            return Err(LookupVerifyError::InvalidInclusionProof);
        }
        if let Some(prev) = self.items.last() {
            // Slots are not consecutive but increasing
            // Column indices are not consecutive but increasing
            match data_column.slot().cmp(&prev.slot()) {
                Ordering::Greater => {} // Ok
                Ordering::Equal => {
                    match data_column.index.cmp(&prev.index) {
                        Ordering::Greater => {} // Ok
                        Ordering::Equal => {
                            return Err(LookupVerifyError::DuplicatedData(
                                data_column.slot(),
                                data_column.index,
                            ));
                        }
                        Ordering::Less => {
                            return Err(LookupVerifyError::NotSorted("descending indices"));
                        }
                    }
                }
                Ordering::Less => {
                    return Err(LookupVerifyError::NotSorted("descending slots"));
                }
            }
        }

        self.items.push(data_column);

        Ok(self.items.len() >= self.request.count as usize * self.request.columns.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
