use parking_lot::RwLock;
use std::collections::HashMap;
use types::Epoch;

/// Maintains a list of data column custody requirements for a given epoch.
///
/// Each time the node transitions to a new epoch, `register_epoch` must be called to populate
/// custody requirements for the new epoch.
#[derive(Default, Debug)]
pub struct DataColumnCustodyTracker(pub RwLock<HashMap<Epoch, Vec<u64>>>);

impl DataColumnCustodyTracker {
    pub fn register_epoch(&self, epoch: Epoch, data_column_ids: Vec<u64>) {
        let mut map = self.0.write();
        map.insert(epoch, data_column_ids);
    }

    pub fn custody_requirements_for_epoch(&self, epoch: &Epoch) -> Option<Vec<u64>> {
        self.0.read().get(epoch).cloned()
    }

    pub fn prune_epoch(&self, epoch: &Epoch) {
        let mut map = self.0.write();
        map.remove(epoch);
    }
}
