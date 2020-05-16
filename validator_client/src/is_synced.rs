use remote_beacon_node::RemoteBeaconNode;
use rest_types::SyncingResponse;
use slog::{debug, error, Logger};
use slot_clock::SlotClock;
use types::EthSpec;

/// A distance in slots.
const SYNC_TOLERANCE: u64 = 4;

/// Returns `true` if the beacon node is synced and ready for action.
///
/// Returns `false` if:
///
///  - The beacon node is unreachable.
///  - The beacon node indicates that it is syncing **AND** it is more than `SYNC_TOLERANCE` behind
///  the highest known slot.
///
///  The second condition means the even if the beacon node thinks that it's syncing, we'll still
///  try to use it if it's close enough to the head.
pub async fn is_synced<T: SlotClock, E: EthSpec>(
    beacon_node: &RemoteBeaconNode<E>,
    slot_clock: &T,
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

            let now = if let Some(slot) = slot_clock.now() {
                slot
            } else {
                // There's no good reason why we shouldn't be able to read the slot clock, so we'll
                // indicate we're not synced if that's the case.
                return false;
            };

            if sync_status.current_slot + SYNC_TOLERANCE >= now {
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
