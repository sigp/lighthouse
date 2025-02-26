pub mod database;
pub mod server;
pub mod updater;

use crate::database::watch_types::WatchSlot;
use crate::updater::error::Error;

pub use database::{
    get_all_suboptimal_attestations_for_epoch, get_attestation_by_index, get_attestation_by_pubkey,
    get_highest_attestation, get_lowest_attestation, insert_batch_suboptimal_attestations,
    WatchAttestation, WatchSuboptimalAttestation,
};

pub use server::{attestation_routes, blockprint_attestation_routes};

use eth2::BeaconNodeHttpClient;
use types::Epoch;

/// Sends a request to `lighthouse/analysis/attestation_performance`.
/// Formats the response into a vector of `WatchSuboptimalAttestation`.
///
/// Any attestations with `source == true && head == true && target == true` are ignored.
pub async fn get_attestation_performances(
    bn: &BeaconNodeHttpClient,
    start_epoch: Epoch,
    end_epoch: Epoch,
    slots_per_epoch: u64,
) -> Result<Vec<WatchSuboptimalAttestation>, Error> {
    let mut output = Vec::new();
    let result = bn
        .get_lighthouse_analysis_attestation_performance(
            start_epoch,
            end_epoch,
            "global".to_string(),
        )
        .await?;
    for index in result {
        for epoch in index.epochs {
            if epoch.1.active {
                // Check if the attestation is suboptimal.
                if !epoch.1.source || !epoch.1.head || !epoch.1.target {
                    output.push(WatchSuboptimalAttestation {
                        epoch_start_slot: WatchSlot::from_slot(
                            Epoch::new(epoch.0).start_slot(slots_per_epoch),
                        ),
                        index: index.index as i32,
                        source: epoch.1.source,
                        head: epoch.1.head,
                        target: epoch.1.target,
                    })
                }
            }
        }
    }
    Ok(output)
}
