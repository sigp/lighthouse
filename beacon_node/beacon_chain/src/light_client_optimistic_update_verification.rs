use crate::{
    beacon_chain::MAXIMUM_GOSSIP_CLOCK_DISPARITY, BeaconChain, BeaconChainError, BeaconChainTypes,
};
use derivative::Derivative;
use slot_clock::SlotClock;
use std::time::Duration;
use strum::AsRefStr;
use types::{
    light_client_update::Error as LightClientUpdateError, LightClientOptimisticUpdate, Slot,
};

/// Returned when a light client optimistic update was not successfully verified. It might not have been verified for
/// two reasons:
///
/// - The light client optimistic message is malformed or inappropriate for the context (indicated by all variants
///   other than `BeaconChainError`).
/// - The application encountered an internal error whilst attempting to determine validity
///   (the `BeaconChainError` variant)
#[derive(Debug, AsRefStr)]
pub enum Error {
    /// Light client optimistic update message with a lower or equal optimistic_header slot already forwarded.
    OptimisticUpdateAlreadySeen,
    /// The light client optimistic message was received is prior to one-third of slot duration passage. (with
    /// respect to the gossip clock disparity and slot clock duration).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    TooEarly,
    /// Light client optimistic update message does not match the locally constructed one.
    ///
    /// ## Peer Scoring
    ///
    InvalidLightClientOptimisticUpdate,
    /// Signature slot start time is none.
    SigSlotStartIsNone,
    /// Failed to construct a LightClientOptimisticUpdate from state.
    FailedConstructingUpdate,
    /// Beacon chain error occured.
    BeaconChainError(BeaconChainError),
    LightClientUpdateError(LightClientUpdateError),
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChainError(e)
    }
}

impl From<LightClientUpdateError> for Error {
    fn from(e: LightClientUpdateError) -> Self {
        Error::LightClientUpdateError(e)
    }
}

/// Wraps a `LightClientOptimisticUpdate` that has been verified for propagation on the gossip network.
#[derive(Derivative)]
#[derivative(Clone(bound = "T: BeaconChainTypes"))]
pub struct VerifiedLightClientOptimisticUpdate<T: BeaconChainTypes> {
    light_client_optimistic_update: LightClientOptimisticUpdate<T::EthSpec>,
    seen_timestamp: Duration,
}

impl<T: BeaconChainTypes> VerifiedLightClientOptimisticUpdate<T> {
    /// Returns `Ok(Self)` if the `light_client_optimistic_update` is valid to be (re)published on the gossip
    /// network.
    pub fn verify(
        light_client_optimistic_update: LightClientOptimisticUpdate<T::EthSpec>,
        chain: &BeaconChain<T>,
        seen_timestamp: Duration,
    ) -> Result<Self, Error> {
        let gossiped_optimistic_slot = light_client_optimistic_update.attested_header.slot;
        let one_third_slot_duration = Duration::new(chain.spec.seconds_per_slot / 3, 0);
        let signature_slot = light_client_optimistic_update.signature_slot;
        let start_time = chain.slot_clock.start_of(signature_slot);
        let mut latest_seen_optimistic_update = chain.latest_seen_optimistic_update.lock();

        let head = chain.canonical_head.cached_head();
        let head_block = &head.snapshot.beacon_block;
        let attested_block_root = head_block.message().parent_root();
        let attested_block = chain
            .get_blinded_block(&attested_block_root)?
            .ok_or(Error::FailedConstructingUpdate)?;

        let attested_state = chain
            .get_state(&attested_block.state_root(), Some(attested_block.slot()))?
            .ok_or(Error::FailedConstructingUpdate)?;
        let latest_seen_optimistic_update_slot = match latest_seen_optimistic_update.as_ref() {
            Some(update) => update.attested_header.slot,
            None => Slot::new(0),
        };

        // verify that no other optimistic_update with a lower or equal
        // optimistic_header.slot was already forwarded on the network
        if gossiped_optimistic_slot <= latest_seen_optimistic_update_slot {
            return Err(Error::OptimisticUpdateAlreadySeen);
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

        let optimistic_update =
            LightClientOptimisticUpdate::new(&chain.spec, head_block, &attested_state)?;

        // verify that the gossiped optimistic update is the same as the locally constructed one.
        if optimistic_update != light_client_optimistic_update {
            return Err(Error::InvalidLightClientOptimisticUpdate);
        }

        *latest_seen_optimistic_update = Some(light_client_optimistic_update.clone());

        Ok(Self {
            light_client_optimistic_update,
            seen_timestamp,
        })
    }
}
