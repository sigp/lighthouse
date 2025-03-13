pub mod cli;
pub mod export;
pub mod import;
pub mod verify;

use eth2::{types::Slot, BeaconNodeHttpClient};

const DEFAULT_BEACON_NODE: &str = "http://localhost:5052";

async fn ensure_node_synced(client: &BeaconNodeHttpClient) -> Result<(Slot, bool), String> {
    let res = client
        .get_node_syncing()
        .await
        .map_err(|e| format!("{e:?}"))?
        .data;

    Ok((res.head_slot, !res.is_syncing))
}
