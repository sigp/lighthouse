use beacon_chain::{BeaconChain, BeaconChainTypes};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use types::{EthSpec, Slot};
use warp_utils::reject::{custom_bad_request, custom_server_error};

#[derive(Debug, Deserialize, Serialize)]
pub struct CustodyResponse {
    pub earliest_custodied_data_column_slot: Slot,
    // TODO: more fields
}

pub fn info<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
) -> Result<CustodyResponse, warp::Rejection> {
    if !chain.spec.is_fulu_scheduled() {
        return Err(custom_bad_request("Fulu is not scheduled".to_string()));
    }

    let data_column_custody_info = chain
        .store
        .get_data_column_custody_info()
        .map_err(|e| custom_server_error(format!("error reading data column custody info: {e:?}")))?
        .ok_or_else(|| custom_server_error("data column custody info missing".to_string()))?;

    let column_data_availability_boundary = chain
        .column_data_availability_boundary()
        .ok_or_else(|| custom_server_error("unreachable: Fulu should be enabled".to_string()))?;

    let earliest_custodied_data_column_slot = data_column_custody_info
        .earliest_data_column_slot
        .unwrap_or_else(|| {
            column_data_availability_boundary.start_slot(T::EthSpec::slots_per_epoch())
        });

    Ok(CustodyResponse {
        earliest_custodied_data_column_slot,
    })
}
