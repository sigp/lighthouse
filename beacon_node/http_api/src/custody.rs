use beacon_chain::{BeaconChain, BeaconChainTypes};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use types::{EthSpec, Slot};
use warp_utils::reject::{custom_bad_request, custom_server_error};

#[derive(Debug, Deserialize, Serialize)]
pub struct CustodyResponse {
    pub earliest_custodied_data_column_slot: Slot,
    #[serde(with = "serde_utils::quoted_u64")]
    pub custody_group_count: u64,
    #[serde(with = "serde_utils::quoted_u64_vec")]
    pub custody_columns: Vec<u64>,
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
    let earliest_custodied_data_column_epoch =
        earliest_custodied_data_column_slot.epoch(T::EthSpec::slots_per_epoch());

    // Compute the custody columns and the CGC *at the earliest custodied slot*. The node might
    // have some columns prior to this, but this value is the most up-to-date view of the data the
    // node is custodying.
    let custody_context = chain.data_availability_checker.custody_context();
    let custody_columns = custody_context
        .custody_columns_for_epoch(Some(earliest_custodied_data_column_epoch), &chain.spec)
        .to_vec();
    let custody_group_count = custody_context
        .custody_group_count_at_epoch(earliest_custodied_data_column_epoch, &chain.spec);

    Ok(CustodyResponse {
        earliest_custodied_data_column_slot,
        custody_group_count,
        custody_columns,
    })
}
