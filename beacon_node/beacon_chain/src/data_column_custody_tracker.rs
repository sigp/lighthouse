use parking_lot::RwLock;

/// Maintains a list of data column custody requirements.
///
/// Each time the node transitions to a new set of data column subnets, `set_custody_requirements` must be called to populate
/// custody requirements.
#[derive(Default, Debug)]
pub struct DataColumnCustodyTracker {
    data_column_ids: RwLock<Vec<u64>>,
}

impl DataColumnCustodyTracker {
    pub fn set_custody_requirements(&self, data_column_ids: Vec<u64>) {
        let mut write_guard = self.data_column_ids.write();
        *write_guard = data_column_ids;
    }

    pub fn get_custody_requirements(&self) -> Vec<u64> {
        self.data_column_ids.read().clone()
    }
}
