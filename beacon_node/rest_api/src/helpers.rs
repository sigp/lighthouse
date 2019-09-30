use crate::{ApiError, ApiResult};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use bls::PublicKey;
use eth2_libp2p::{PubsubMessage, Topic};
use eth2_libp2p::{
    BEACON_ATTESTATION_TOPIC, BEACON_BLOCK_TOPIC, TOPIC_ENCODING_POSTFIX, TOPIC_PREFIX,
};
use hex;
use http::header;
use hyper::{Body, Request};
use network::NetworkMessage;
use parking_lot::RwLock;
use ssz::Encode;
use std::sync::Arc;
use store::{iter::AncestorIter, Store};
use tokio::sync::mpsc;
use types::{Attestation, BeaconBlock, BeaconState, EthSpec, Hash256, RelativeEpoch, Slot};

/// Parse a slot from a `0x` preixed string.
///
/// E.g., `"1234"`
pub fn parse_slot(string: &str) -> Result<Slot, ApiError> {
    string
        .parse::<u64>()
        .map(Slot::from)
        .map_err(|e| ApiError::BadRequest(format!("Unable to parse slot: {:?}", e)))
}

/// Checks the provided request to ensure that the `content-type` header.
///
/// The content-type header should either be omitted, in which case JSON is assumed, or it should
/// explicity specify `application/json`. If anything else is provided, an error is returned.
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

/// Parse a root from a `0x` preixed string.
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
            "Root must have a  '0x' prefix".to_string(),
        ))
    }
}

/// Parse a PublicKey from a `0x` prefixed hex string
pub fn parse_pubkey(string: &str) -> Result<PublicKey, ApiError> {
    const PREFIX: &str = "0x";
    if string.starts_with(PREFIX) {
        let pubkey_bytes = hex::decode(string.trim_start_matches(PREFIX))
            .map_err(|e| ApiError::BadRequest(format!("Invalid hex string: {:?}", e)))?;
        let pubkey = PublicKey::from_bytes(pubkey_bytes.as_slice()).map_err(|e| {
            ApiError::BadRequest(format!("Unable to deserialize public key: {:?}.", e))
        })?;
        Ok(pubkey)
    } else {
        Err(ApiError::BadRequest(
            "Public key must have a  '0x' prefix".to_string(),
        ))
    }
}

/// Returns the root of the `BeaconBlock` in the canonical chain of `beacon_chain` at the given
/// `slot`, if possible.
///
/// May return a root for a previous slot, in the case of skip slots.
pub fn block_root_at_slot<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    target: Slot,
) -> Option<Hash256> {
    beacon_chain
        .rev_iter_block_roots()
        .take_while(|(_root, slot)| *slot >= target)
        .find(|(_root, slot)| *slot == target)
        .map(|(root, _slot)| root)
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

pub fn implementation_pending_response(_req: Request<Body>) -> ApiResult {
    Err(ApiError::NotImplemented(
        "API endpoint has not yet been implemented, but is planned to be soon.".to_owned(),
    ))
}

pub fn get_beacon_chain_from_request<T: BeaconChainTypes + 'static>(
    req: &Request<Body>,
) -> Result<(Arc<BeaconChain<T>>), ApiError> {
    // Get beacon state
    let beacon_chain = req
        .extensions()
        .get::<Arc<BeaconChain<T>>>()
        .ok_or_else(|| ApiError::ServerError("Beacon chain extension missing".into()))?;

    Ok(beacon_chain.clone())
}

pub fn get_logger_from_request(req: &Request<Body>) -> slog::Logger {
    let log = req
        .extensions()
        .get::<slog::Logger>()
        .expect("Should always get the logger from the request, since we put it in there.");
    log.to_owned()
}

pub fn publish_beacon_block_to_network<T: BeaconChainTypes + 'static>(
    chan: Arc<RwLock<mpsc::UnboundedSender<NetworkMessage>>>,
    block: BeaconBlock<T::EthSpec>,
) -> Result<(), ApiError> {
    // create the network topic to send on
    let topic_string = format!(
        "/{}/{}/{}",
        TOPIC_PREFIX, BEACON_BLOCK_TOPIC, TOPIC_ENCODING_POSTFIX
    );
    let topic = Topic::new(topic_string);
    let message = PubsubMessage::Block(block.as_ssz_bytes());

    // Publish the block to the p2p network via gossipsub.
    if let Err(e) = chan.write().try_send(NetworkMessage::Publish {
        topics: vec![topic],
        message,
    }) {
        return Err(ApiError::ServerError(format!(
            "Unable to send new block to network: {:?}",
            e
        )));
    }

    Ok(())
}

pub fn publish_attestation_to_network<T: BeaconChainTypes + 'static>(
    chan: Arc<RwLock<mpsc::UnboundedSender<NetworkMessage>>>,
    attestation: Attestation<T::EthSpec>,
) -> Result<(), ApiError> {
    // create the network topic to send on
    let topic_string = format!(
        "/{}/{}/{}",
        TOPIC_PREFIX, BEACON_ATTESTATION_TOPIC, TOPIC_ENCODING_POSTFIX
    );
    let topic = Topic::new(topic_string);
    let message = PubsubMessage::Attestation(attestation.as_ssz_bytes());

    // Publish the attestation to the p2p network via gossipsub.
    if let Err(e) = chan.write().try_send(NetworkMessage::Publish {
        topics: vec![topic],
        message,
    }) {
        return Err(ApiError::ServerError(format!(
            "Unable to send new attestation to network: {:?}",
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
