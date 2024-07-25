use crate::beacon_node_fallback::CandidateError;
use eth2::{types::Slot, BeaconNodeHttpClient};
use slog::{warn, Logger};

pub async fn check_node_health(
    beacon_node: &BeaconNodeHttpClient,
    log: &Logger,
) -> Result<(Slot, bool, bool), CandidateError> {
    let resp = match beacon_node.get_node_syncing().await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(
                log,
                "Unable connect to beacon node";
                "error" => %e
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
