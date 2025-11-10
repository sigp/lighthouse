use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::lighthouse::CustodyInfo;
use std::sync::Arc;
use types::EthSpec;
use warp_utils::reject::{custom_bad_request, custom_server_error};

pub fn info<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
) -> Result<CustodyInfo, warp::Rejection> {
    if !chain.spec.is_fulu_scheduled() {
        return Err(custom_bad_request("Fulu is not scheduled".to_string()));
    }

    let opt_data_column_custody_info = chain
        .store
        .get_data_column_custody_info()
        .map_err(|e| custom_server_error(format!("error reading DataColumnCustodyInfo: {e:?}")))?;

    let column_data_availability_boundary = chain
        .column_data_availability_boundary()
        .ok_or_else(|| custom_server_error("unreachable: Fulu should be enabled".to_string()))?;

    let earliest_custodied_data_column_slot = opt_data_column_custody_info
        .and_then(|info| info.earliest_data_column_slot)
        .unwrap_or_else(|| {
            // If there's no data column custody info/earliest data column slot, it means *column*
            // backfill is not running. Block backfill could still be running, so our earliest
            // available column is either the oldest block slot or the DA boundary, whichever is
            // more recent.
            let oldest_block_slot = chain.store.get_anchor_info().oldest_block_slot;
            column_data_availability_boundary
                .start_slot(T::EthSpec::slots_per_epoch())
                .max(oldest_block_slot)
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

    Ok(CustodyInfo {
        earliest_custodied_data_column_slot,
        custody_group_count,
        custody_columns,
    })
}
