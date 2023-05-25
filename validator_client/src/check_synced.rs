use crate::beacon_node_fallback::CandidateError;
use eth2::BeaconNodeHttpClient;
use slog::{debug, error, warn, Logger};
use slot_clock::SlotClock;

/// A distance in slots.
const SYNC_TOLERANCE: u64 = 4;

/// Returns
///
///  `Ok(())`                           if the beacon node is synced and ready for action,
///  `Err(CandidateError::Offline)`     if the beacon node is unreachable,
///  `Err(CandidateError::NotSynced)`   if the beacon node indicates that it is syncing **AND**
///                                         it is more than `SYNC_TOLERANCE` behind the highest
///                                         known slot.
///
///  The second condition means the even if the beacon node thinks that it's syncing, we'll still
///  try to use it if it's close enough to the head.
pub async fn check_synced<T: SlotClock>(
    beacon_node: &BeaconNodeHttpClient,
    slot_clock: &T,
    log_opt: Option<&Logger>,
) -> Result<(), CandidateError> {
    let resp = match beacon_node.get_node_syncing().await {
        Ok(resp) => resp,
        Err(e) => {
            if let Some(log) = log_opt {
                warn!(
                    log,
                    "Unable connect to beacon node";
                    "error" => %e
                )
            }

            return Err(CandidateError::Offline);
        }
    };

    // Default EL status to "online" for backwards-compatibility with BNs that don't include it.
    let el_offline = resp.data.el_offline.unwrap_or(false);
    let bn_is_synced = !resp.data.is_syncing || (resp.data.sync_distance.as_u64() < SYNC_TOLERANCE);
    let is_synced = bn_is_synced && !el_offline;

    if let Some(log) = log_opt {
        if !is_synced {
            debug!(
                log,
                "Beacon node sync status";
                "status" => format!("{:?}", resp),
            );

            warn!(
                log,
                "Beacon node is not synced";
                "sync_distance" => resp.data.sync_distance.as_u64(),
                "head_slot" => resp.data.head_slot.as_u64(),
                "endpoint" => %beacon_node,
                "el_offline" => el_offline,
            );
        }

        if let Some(local_slot) = slot_clock.now() {
            let remote_slot = resp.data.head_slot + resp.data.sync_distance;
            if remote_slot + 1 < local_slot || local_slot + 1 < remote_slot {
                error!(
                    log,
                    "Time discrepancy with beacon node";
                    "msg" => "check the system time on this host and the beacon node",
                    "beacon_node_slot" => remote_slot,
                    "local_slot" => local_slot,
                    "endpoint" => %beacon_node,
                );
            }
        }
    }

    if is_synced {
        Ok(())
    } else {
        Err(CandidateError::NotSynced)
    }
}
