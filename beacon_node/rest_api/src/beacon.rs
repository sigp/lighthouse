use super::{success_response, ApiResult};
// use crate::ApiRequest;
use crate::ApiError;
use crate::UrlQuery;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use hyper::{Body, Request};
use std::sync::Arc;
use store::{iter::StateRootsIterator, Store};
use types::{BeaconState, EthSpec, RelativeEpoch, Slot};

/// Read the version string from the current Lighthouse build.
pub fn get_state<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".to_string()))?;

    let query_params = ["root", "slot"];
    let (key, value) = UrlQuery::from_request(&req)?.first_of(&query_params)?;

    let json: String = match (key.as_ref(), value) {
        ("slot", value) => {
            let slot = value
                .parse::<u64>()
                .map_err(|_| ApiError::InvalidQueryParams("Unable to parse slot".to_string()))?;

            let head_slot = beacon_chain.head().beacon_block.slot;
            let current_slot = beacon_chain
                .read_slot_clock()
                .ok_or_else(|| ApiError::ServerError("Unable to read slot clock".to_string()))?;

            // There are four scenarios when obtaining a state for a given slot:
            //
            // 1. The request slot is in the future.
            // 2. The request slot is the same as the best block (head) slot.
            // 3. The request slot is prior to the head slot.
            // 4. The request slot is later than the head slot.
            if current_slot < slot {
                // 1. The request slot is in the future. Reject the request.
                //
                // We could actually speculate about future states by skipping slots, however
                // that's likely to cause confusion for API users.
                return Err(ApiError::InvalidQueryParams(format!(
                    "Requested slot {} is past the current slot {}",
                    slot, current_slot
                )));
            } else if head_slot == slot {
                // 2. The request slot is the same as the best block (head) slot.
                //
                // The head state is stored in memory, it is serialized.
                serde_json::to_string(&beacon_chain.head().beacon_state).map_err(|e| {
                    ApiError::ServerError(format!("Unable to serialize BeaconState: {:?}", e))
                })?
            } else if head_slot > slot {
                // 3. The request slot is prior to the head slot.
                //
                // Iterate through the state roots on the head state to find the root for that
                // slot. Once the root is found, load it from the database.
                let root = StateRootsIterator::new(
                    beacon_chain.store.clone(),
                    &beacon_chain.head().beacon_state,
                    beacon_chain.head().beacon_state.slot,
                )
                .find(|(_root, found_slot)| *found_slot == slot)
                .map(|(root, _slot)| root)
                .ok_or_else(|| {
                    ApiError::NotFound(format!("Unable to find state at slot {}", slot))
                })?;

                let state: BeaconState<T::EthSpec> =
                    beacon_chain.store.get(&root)?.ok_or_else(|| {
                        ApiError::NotFound(format!("Unable to find state at root {}", root))
                    })?;

                serde_json::to_string(&state).map_err(|e| {
                    ApiError::ServerError(format!("Unable to serialize BeaconState: {:?}", e))
                })?
            } else {
                // 4. The request slot is later than the head slot.
                //
                // Use `per_slot_processing` to advance the head state to the present slot,
                // assuming that all slots do not contain a block (i.e., they are skipped slots).
                let mut state = beacon_chain.head().beacon_state.clone();
                let spec = &T::EthSpec::default_spec();

                for _ in state.slot.as_u64()..slot {
                    // Ensure the next epoch state caches are built in case of an epoch transition.
                    state.build_committee_cache(RelativeEpoch::Next, spec)?;

                    state_processing::per_slot_processing(&mut state, spec)?;
                }

                serde_json::to_string(&state).map_err(|e| {
                    ApiError::ServerError(format!("Unable to serialize BeaconState: {:?}", e))
                })?
            }
        }
        _ => {
            return Err(ApiError::NotImplemented(
                "Only slot is implemented".to_string(),
            ))
        }
    };

    Ok(success_response(Body::from(json)))
}
