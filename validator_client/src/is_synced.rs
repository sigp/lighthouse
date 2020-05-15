use remote_beacon_node::RemoteBeaconNode;
use rest_types::SyncingResponse;
use slog::{debug, error, Logger};
use types::EthSpec;

const SYNC_TOLERANCE: u64 = 4;

pub async fn is_synced<E: EthSpec>(
    beacon_node: &RemoteBeaconNode<E>,
    log_opt: Option<&Logger>,
) -> bool {
    let resp = match beacon_node.http.node().syncing_status().await {
        Ok(resp) => resp,
        Err(e) => {
            if let Some(log) = log_opt {
                error!(
                    log,
                    "Unable connect to beacon node";
                    "error" => format!("{:?}", e)
                )
            }

            return false;
        }
    };

    match &resp {
        SyncingResponse {
            is_syncing: false, ..
        } => true,
        SyncingResponse {
            is_syncing: true,
            sync_status,
        } => {
            if let Some(log) = log_opt {
                debug!(
                    log,
                    "Beacon node sync status";
                    "status" => format!("{:?}", resp),
                );
            }

            if sync_status.current_slot + SYNC_TOLERANCE >= sync_status.highest_slot {
                true
            } else {
                if let Some(log) = log_opt {
                    error!(
                        log,
                        "Beacon node is syncing";
                        "msg" => "not receiving new duties",
                        "target_slot" => sync_status.highest_slot.as_u64(),
                        "current_slot" => sync_status.current_slot.as_u64(),
                    );
                }
                false
            }
        }
    }
}
