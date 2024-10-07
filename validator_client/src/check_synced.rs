use crate::beacon_node_fallback::CandidateError;
use eth2::{types::Slot, BeaconNodeHttpClient}
use slog::Logger;
use slot_clock::SlotClock;
use tracing::{debug, error, warn};

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
    log: &Logger,
) -> Result<(Slot, bool, bool), CandidateError> {
    let resp = match beacon_node.get_node_syncing().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(
                error = %e,
                "Unable connect to beacon node"
            );

            return Err(CandidateError::Offline);
        }
    };

    Ok((
        resp.data.head_slot,
        resp.data.is_optimistic,
        resp.data.el_offline,
    ))
}
