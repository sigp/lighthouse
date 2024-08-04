use std::{collections::HashMap, sync::Arc};

use slot_clock::SlotClock;
use types::{AttestationData, CommitteeIndex, EthSpec, ForkName, Slot};

use crate::{
    beacon_node_fallback::{BeaconNodeFallback, OfflineOnFailure, RequireSynced},
    http_metrics::metrics,
};

/// The AttestationDataService is responsible for downloading and caching attestation data at a given slot
/// for a range of committee indexes. It also helps prevent us from re-downloading identical attestation data.
pub struct AttestationDataService<T: SlotClock, E: EthSpec> {
    attestation_data_by_committee: HashMap<CommitteeIndex, AttestationData>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
}

impl<T: SlotClock, E: EthSpec> AttestationDataService<T, E> {
    pub fn new(beacon_nodes: Arc<BeaconNodeFallback<T, E>>) -> Self {
        Self {
            attestation_data_by_committee: HashMap::new(),
            beacon_nodes,
        }
    }

    /// Get previously downloaded attestation data by a given committee index. If the Electra fork is enabled
    /// we don't care about the committee index
    pub fn get_data_by_committee_index(
        &self,
        committee_index: CommitteeIndex,
        fork_name: ForkName,
    ) -> Option<AttestationData> {
        if fork_name.electra_enabled() {
            let data = self.attestation_data_by_committee.iter().next();
            if let Some((_, data)) = data {
                return Some(data.clone());
            }
            None
        } else {
            self.attestation_data_by_committee
                .get(&committee_index)
                .cloned()
        }
    }

    /// Download attestation data for this slot/committee index from the beacon node.
    pub async fn download_data(
        &mut self,
        committee_index: CommitteeIndex,
        slot: Slot,
        fork_name: ForkName,
    ) -> Result<(), String> {
        // If we've already downloaded data for this committee index OR electra is enabled and
        // we've already downloaded data for this slot, there's no need to re-download the data.
        if let Some(_) = self.get_data_by_committee_index(committee_index, fork_name) {
            return Ok(());
        }

        let attestation_data = self
            .beacon_nodes
            .first_success(
                RequireSynced::No,
                OfflineOnFailure::Yes,
                |beacon_node| async move {
                    let _timer = metrics::start_timer_vec(
                        &metrics::ATTESTATION_SERVICE_TIMES,
                        &[metrics::ATTESTATIONS_HTTP_GET],
                    );
                    beacon_node
                        .get_validator_attestation_data(slot, committee_index)
                        .await
                        .map_err(|e| format!("Failed to produce attestation data: {:?}", e))
                        .map(|result| result.data)
                },
            )
            .await
            .map_err(|e| e.to_string())?;

        self.attestation_data_by_committee
            .insert(committee_index, attestation_data);

        Ok(())
    }
}
