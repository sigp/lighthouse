use crate::ApiError;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use store::{iter::AncestorIter, Store};
use types::{BeaconState, EthSpec, Hash256, RelativeEpoch, Slot};

/// Parse a slot from a `0x` preixed string.
///
/// E.g., `"1234"`
pub fn parse_slot(string: &str) -> Result<Slot, ApiError> {
    string
        .parse::<u64>()
        .map(Slot::from)
        .map_err(|e| ApiError::InvalidQueryParams(format!("Unable to parse slot: {:?}", e)))
}

/// Parse a root from a `0x` preixed string.
///
/// E.g., `"0x0000000000000000000000000000000000000000000000000000000000000000"`
pub fn parse_root(string: &str) -> Result<Hash256, ApiError> {
    const PREFIX: &str = "0x";

    if string.starts_with(PREFIX) {
        let trimmed = string.trim_start_matches(PREFIX);
        trimmed
            .parse()
            .map_err(|e| ApiError::InvalidQueryParams(format!("Unable to parse root: {:?}", e)))
    } else {
        Err(ApiError::InvalidQueryParams(
            "Root must have a  '0x' prefix".to_string(),
        ))
    }
}

/// Returns a `BeaconState` and it's root in the canonical chain of `beacon_chain` at the given
/// `slot`, if possible.
///
/// Will not return a state if the request slot is in the future. Will return states higher than
/// the current head by skipping slots.
pub fn state_at_slot<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    slot: Slot,
) -> Result<(Hash256, BeaconState<T::EthSpec>), ApiError> {
    let head_state = &beacon_chain.head().beacon_state;

    if head_state.slot == slot {
        // The request slot is the same as the best block (head) slot.

        // I'm not sure if this `.clone()` will be optimized out. If not, it seems unnecessary.
        Ok((
            beacon_chain.head().beacon_state_root,
            beacon_chain.head().beacon_state.clone(),
        ))
    } else {
        let root = state_root_at_slot(beacon_chain, slot)?;

        let state: BeaconState<T::EthSpec> = beacon_chain
            .store
            .get(&root)?
            .ok_or_else(|| ApiError::NotFound(format!("Unable to find state at root {}", root)))?;

        Ok((root, state))
    }
}

/// Returns the root of the `BeaconState` in the canonical chain of `beacon_chain` at the given
/// `slot`, if possible.
///
/// Will not return a state root if the request slot is in the future. Will return state roots
/// higher than the current head by skipping slots.
pub fn state_root_at_slot<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    slot: Slot,
) -> Result<Hash256, ApiError> {
    let head_state = &beacon_chain.head().beacon_state;
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
        // We could actually speculate about future state roots by skipping slots, however that's
        // likely to cause confusion for API users.
        Err(ApiError::InvalidQueryParams(format!(
            "Requested slot {} is past the current slot {}",
            slot, current_slot
        )))
    } else if head_state.slot == slot {
        // 2. The request slot is the same as the best block (head) slot.
        //
        // The head state root is stored in memory, return a reference.
        Ok(beacon_chain.head().beacon_state_root)
    } else if head_state.slot > slot {
        // 3. The request slot is prior to the head slot.
        //
        // Iterate through the state roots on the head state to find the root for that
        // slot. Once the root is found, load it from the database.
        Ok(head_state
            .try_iter_ancestor_roots(beacon_chain.store.clone())
            .ok_or_else(|| ApiError::ServerError("Failed to create roots iterator".to_string()))?
            .find(|(_root, s)| *s == slot)
            .map(|(root, _slot)| root)
            .ok_or_else(|| ApiError::NotFound(format!("Unable to find state at slot {}", slot)))?)
    } else {
        // 4. The request slot is later than the head slot.
        //
        // Use `per_slot_processing` to advance the head state to the present slot,
        // assuming that all slots do not contain a block (i.e., they are skipped slots).
        let mut state = beacon_chain.head().beacon_state.clone();
        let spec = &T::EthSpec::default_spec();

        for _ in state.slot.as_u64()..slot.as_u64() {
            // Ensure the next epoch state caches are built in case of an epoch transition.
            state.build_committee_cache(RelativeEpoch::Next, spec)?;

            state_processing::per_slot_processing(&mut state, spec)?;
        }

        // Note: this is an expensive operation. Once the tree hash cache is implement it may be
        // used here.
        Ok(state.canonical_root())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_root_works() {
        assert_eq!(
            parse_root("0x0000000000000000000000000000000000000000000000000000000000000000"),
            Ok(Hash256::zero())
        );
        assert_eq!(
            parse_root("0x000000000000000000000000000000000000000000000000000000000000002a"),
            Ok(Hash256::from_low_u64_be(42))
        );
        assert!(
            parse_root("0000000000000000000000000000000000000000000000000000000000000042").is_err()
        );
        assert!(parse_root("0x").is_err());
        assert!(parse_root("0x00").is_err());
    }

    #[test]
    fn parse_slot_works() {
        assert_eq!(parse_slot("0"), Ok(Slot::new(0)));
        assert_eq!(parse_slot("42"), Ok(Slot::new(42)));
        assert_eq!(parse_slot("10000000"), Ok(Slot::new(10_000_000)));
        assert!(parse_slot("cats").is_err());
    }
}
