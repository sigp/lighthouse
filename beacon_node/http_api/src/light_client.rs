pub fn build_light_client_updates_response(
    chain: Arc<BeaconChain>,
    query: LightClientUpdatesQuery,
    accept_header: Option<api_types::Accept>,
) {
    let light_client_updates = chain
        .get_beacon_light_client_updates(query.start_period, query.count)
        .ok_or_else(|| {
            warp_utils::reject::custom_not_found("No LightClientUpdates found".to_string())
        })?;

    let fork_versioned_response = light_client_updates
        .iter()
        .map(|update| map_light_client_update_to_response(chain, update))
        .collect();
}

fn map_light_client_update_to_response(
    chain: Arc<BeaconChain>,
    light_client_update: &LightClientUpdate,
) -> ForkVersionedResponse {
    let fork_name = chain
        .spec
        .fork_name_at_slot::<T::EthSpec>(*light_client_update.signature_slot());

    ForkVersionedResponse {
        version: Some(fork_name),
        metadata: EmptyMetadata {},
        data: update,
    }
}
