use crate::{
    beacon_chain::MAXIMUM_GOSSIP_CLOCK_DISPARITY,
    BeaconChain, BeaconChainError, BeaconChainTypes,
};
use derivative::Derivative;
use slot_clock::SlotClock;
use std::time::Duration;
use strum::AsRefStr;
use types::LightClientFinalityUpdate;
use ssz::Encode;
use slog::debug;

/// Returned when a light client finality update was not successfully verified. It might not have been verified for
/// two reasons:
///
/// - The light client finality message is malformed or inappropriate for the context (indicated by all variants
///   other than `BeaconChainError`).
/// - The application encountered an internal error whilst attempting to determine validity
///   (the `BeaconChainError` variant)
#[derive(Debug, AsRefStr)]
pub enum Error {
    /// Light client finality update message with a lower or equal finalized_header slot already forwarded.
    FinalityUpdateAlreadySeen,
    /// The light client finality message was received is prior to one-third of slot duration passage. (with
    /// respect to the gossip clock disparity and slot clock duration).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    TooEarly,
    /// Light client finality update message does not match the locally constructed one.
    InvalidLightClientFinalityUpdate,
    // Signature slot start time is none.
    SigSlotStartIsNone,
    // Failed to construct a LightClientFinalityUpdate from state.
    FailedConstructingUpdate,
    // Beacon chain error occured.
    BeaconChainError(BeaconChainError),
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChainError(e)
    }
}

/// Wraps a `LightClientFinalityUpdate` that has been verified for propagation on the gossip network.
#[derive(Derivative)]
#[derivative(Clone(bound = "T: BeaconChainTypes"))]
pub struct VerifiedLightClientFinalityUpdate<T: BeaconChainTypes> {
    light_client_finality_update: LightClientFinalityUpdate<T::EthSpec>,
    seen_timestamp: Duration,
}

impl<T: BeaconChainTypes> VerifiedLightClientFinalityUpdate<T> {
    /// Returns `Ok(Self)` if the `light_client_finality_update` is valid to be (re)published on the gossip
    /// network.
    pub fn verify(
        light_client_finality_update: LightClientFinalityUpdate<T::EthSpec>,
        chain: &BeaconChain<T>,
        seen_timestamp: Duration,
    ) -> Result<Self, Error> {
        let gossiped_finality_slot = light_client_finality_update.finalized_header.slot;
        let one_third_slot_duration = Duration::new(chain.spec.seconds_per_slot / 3, 0);
        let signature_slot = light_client_finality_update.signature_slot;
        let mut latest_seen_finality_update = chain.latest_seen_finality_update.lock();
        let start_time = chain.slot_clock.start_of(signature_slot);

        // verify that no other finality_update with a lower or equal
        // finalized_header.slot was already forwarded on the network
        // if gossiped_finality_slot <= latest_seen_update.finalized_head.slot {
        if gossiped_finality_slot <= latest_seen_finality_update.finalized_header.slot {
            return Err(Error::FinalityUpdateAlreadySeen);
        }

        // verify that enough time has passed for the block to have been propagated
        match start_time {
            Some(time) => {
                if seen_timestamp + MAXIMUM_GOSSIP_CLOCK_DISPARITY < time + one_third_slot_duration
                {
                    return Err(Error::TooEarly);
                }
            }
            None => return Err(Error::SigSlotStartIsNone),
        }

        let head = chain.head_snapshot();
        if let Ok(Some(update)) = chain.with_mutable_state_for_block(
            &head.beacon_block,
            head.beacon_block_root,
            |state, cache_hit| {
                state.initialize_tree_hash_cache();
                debug!(
                    chain.log,
                    "Is the block in cache";
                    "cache_hit" => cache_hit,
                );
                
                // TODO: This method is not implemented. Quite frankly I don't know how to implement it.
                Ok(LightClientFinalityUpdate::from_state(state))
            }
        ) {
            *latest_seen_finality_update = update;
        } else {
            return Err(Error::FailedConstructingUpdate);
        }

        // verify that the gossiped finality update is the same as the locally constructed one.
        if latest_seen_finality_update.as_ssz_bytes() != light_client_finality_update.as_ssz_bytes() {
            return Err(Error::InvalidLightClientFinalityUpdate);
        }

        Ok(Self {
            light_client_finality_update,
            seen_timestamp,
        })
    }
}