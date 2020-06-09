use crate::{ApiError, ApiResult, NetworkChannel};
use beacon_chain::{BeaconChain, BeaconChainTypes, StateSkipConfig};
use bls::PublicKeyBytes;
use eth2_libp2p::PubsubMessage;
use hex;
use http::header;
use hyper::{Body, Request};
use itertools::process_results;
use network::NetworkMessage;
use ssz::Decode;
use store::{iter::AncestorIter, Store};
use types::{
    BeaconState, CommitteeIndex, Epoch, EthSpec, Hash256, RelativeEpoch, SignedBeaconBlock, Slot,
};

/// Parse a slot.
///
/// E.g., `"1234"`
pub fn parse_slot(string: &str) -> Result<Slot, ApiError> {
    string
        .parse::<u64>()
        .map(Slot::from)
        .map_err(|e| ApiError::BadRequest(format!("Unable to parse slot: {:?}", e)))
}

/// Parse an epoch.
///
/// E.g., `"13"`
pub fn parse_epoch(string: &str) -> Result<Epoch, ApiError> {
    string
        .parse::<u64>()
        .map(Epoch::from)
        .map_err(|e| ApiError::BadRequest(format!("Unable to parse epoch: {:?}", e)))
}

/// Parse a CommitteeIndex.
///
/// E.g., `"18"`
pub fn parse_committee_index(string: &str) -> Result<CommitteeIndex, ApiError> {
    string
        .parse::<CommitteeIndex>()
        .map_err(|e| ApiError::BadRequest(format!("Unable to parse committee index: {:?}", e)))
}

/// Checks the provided request to ensure that the `content-type` header.
///
/// The content-type header should either be omitted, in which case JSON is assumed, or it should
/// explicitly specify `application/json`. If anything else is provided, an error is returned.
pub fn check_content_type_for_json(req: &Request<Body>) -> Result<(), ApiError> {
    match req.headers().get(header::CONTENT_TYPE) {
        Some(h) if h == "application/json" => Ok(()),
        Some(h) => Err(ApiError::BadRequest(format!(
            "The provided content-type {:?} is not available, this endpoint only supports json.",
            h
        ))),
        _ => Ok(()),
    }
}

/// Parse an SSZ object from some hex-encoded bytes.
///
/// E.g., A signature is `"0x0000000000000000000000000000000000000000000000000000000000000000"`
pub fn parse_hex_ssz_bytes<T: Decode>(string: &str) -> Result<T, ApiError> {
    const PREFIX: &str = "0x";

    if string.starts_with(PREFIX) {
        let trimmed = string.trim_start_matches(PREFIX);
        let bytes = hex::decode(trimmed)
            .map_err(|e| ApiError::BadRequest(format!("Unable to parse SSZ hex: {:?}", e)))?;
        T::from_ssz_bytes(&bytes)
            .map_err(|e| ApiError::BadRequest(format!("Unable to parse SSZ bytes: {:?}", e)))
    } else {
        Err(ApiError::BadRequest(
            "Hex bytes must have a 0x prefix".to_string(),
        ))
    }
}

/// Parse a root from a `0x` prefixed string.
///
/// E.g., `"0x0000000000000000000000000000000000000000000000000000000000000000"`
pub fn parse_root(string: &str) -> Result<Hash256, ApiError> {
    const PREFIX: &str = "0x";

    if string.starts_with(PREFIX) {
        let trimmed = string.trim_start_matches(PREFIX);
        trimmed
            .parse()
            .map_err(|e| ApiError::BadRequest(format!("Unable to parse root: {:?}", e)))
    } else {
        Err(ApiError::BadRequest(
            "Root must have a 0x prefix".to_string(),
        ))
    }
}

/// Parse a PublicKey from a `0x` prefixed hex string
pub fn parse_pubkey_bytes(string: &str) -> Result<PublicKeyBytes, ApiError> {
    const PREFIX: &str = "0x";
    if string.starts_with(PREFIX) {
        let pubkey_bytes = hex::decode(string.trim_start_matches(PREFIX))
            .map_err(|e| ApiError::BadRequest(format!("Invalid hex string: {:?}", e)))?;
        let pubkey = PublicKeyBytes::from_bytes(pubkey_bytes.as_slice()).map_err(|e| {
            ApiError::BadRequest(format!("Unable to deserialize public key: {:?}.", e))
        })?;
        Ok(pubkey)
    } else {
        Err(ApiError::BadRequest(
            "Public key must have a 0x prefix".to_string(),
        ))
    }
}

/// Returns the root of the `SignedBeaconBlock` in the canonical chain of `beacon_chain` at the given
/// `slot`, if possible.
///
/// May return a root for a previous slot, in the case of skip slots.
pub fn block_root_at_slot<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    target: Slot,
) -> Result<Option<Hash256>, ApiError> {
    Ok(process_results(
        beacon_chain.rev_iter_block_roots()?,
        |iter| {
            iter.take_while(|(_, slot)| *slot >= target)
                .find(|(_, slot)| *slot == target)
                .map(|(root, _)| root)
        },
    )?)
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
    let head = beacon_chain.head()?;

    if head.beacon_state.slot == slot {
        Ok((head.beacon_state_root, head.beacon_state))
    } else {
        let root = state_root_at_slot(beacon_chain, slot, StateSkipConfig::WithStateRoots)?;

        let state: BeaconState<T::EthSpec> = beacon_chain
            .store
            .get_state(&root, Some(slot))?
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
    config: StateSkipConfig,
) -> Result<Hash256, ApiError> {
    let head_state = &beacon_chain.head()?.beacon_state;
    let current_slot = beacon_chain
        .slot()
        .map_err(|_| ApiError::ServerError("Unable to read slot clock".to_string()))?;

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
        Err(ApiError::BadRequest(format!(
            "Requested slot {} is past the current slot {}",
            slot, current_slot
        )))
    } else if head_state.slot == slot {
        // 2. The request slot is the same as the best block (head) slot.
        //
        // The head state root is stored in memory, return a reference.
        Ok(beacon_chain.head()?.beacon_state_root)
    } else if head_state.slot > slot {
        // 3. The request slot is prior to the head slot.
        //
        // Iterate through the state roots on the head state to find the root for that
        // slot. Once the root is found, load it from the database.
        process_results(
            head_state
                .try_iter_ancestor_roots(beacon_chain.store.clone())
                .ok_or_else(|| {
                    ApiError::ServerError("Failed to create roots iterator".to_string())
                })?,
            |mut iter| iter.find(|(_, s)| *s == slot).map(|(root, _)| root),
        )?
        .ok_or_else(|| ApiError::NotFound(format!("Unable to find state at slot {}", slot)))
    } else {
        // 4. The request slot is later than the head slot.
        //
        // Use `per_slot_processing` to advance the head state to the present slot,
        // assuming that all slots do not contain a block (i.e., they are skipped slots).
        let mut state = beacon_chain.head()?.beacon_state;
        let spec = &T::EthSpec::default_spec();

        let skip_state_root = match config {
            StateSkipConfig::WithStateRoots => None,
            StateSkipConfig::WithoutStateRoots => Some(Hash256::zero()),
        };

        for _ in state.slot.as_u64()..slot.as_u64() {
            // Ensure the next epoch state caches are built in case of an epoch transition.
            state.build_committee_cache(RelativeEpoch::Next, spec)?;

            state_processing::per_slot_processing(&mut state, skip_state_root, spec)?;
        }

        // Note: this is an expensive operation. Once the tree hash cache is implement it may be
        // used here.
        Ok(state.canonical_root())
    }
}

pub fn implementation_pending_response(_req: Request<Body>) -> ApiResult {
    Err(ApiError::NotImplemented(
        "API endpoint has not yet been implemented, but is planned to be soon.".to_owned(),
    ))
}

pub fn publish_beacon_block_to_network<T: BeaconChainTypes + 'static>(
    chan: NetworkChannel<T::EthSpec>,
    block: SignedBeaconBlock<T::EthSpec>,
) -> Result<(), ApiError> {
    // send the block via SSZ encoding
    let messages = vec![PubsubMessage::BeaconBlock(Box::new(block))];

    // Publish the block to the p2p network via gossipsub.
    if let Err(e) = chan.send(NetworkMessage::Publish { messages }) {
        return Err(ApiError::ServerError(format!(
            "Unable to send new block to network: {:?}",
            e
        )));
    }

    Ok(())
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
