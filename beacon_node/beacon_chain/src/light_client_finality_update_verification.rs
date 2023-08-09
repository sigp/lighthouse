use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use derivative::Derivative;
use slot_clock::SlotClock;
use std::time::Duration;
use strum::AsRefStr;
use types::{
    light_client_update::Error as LightClientUpdateError, LightClientFinalityUpdate, Slot,
};

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
    ///
    /// ## Peer Scoring
    ///
    InvalidLightClientFinalityUpdate,
    /// Signature slot start time is none.
    SigSlotStartIsNone,
    /// Failed to construct a LightClientFinalityUpdate from state.
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
        let start_time = chain.slot_clock.start_of(signature_slot);
        let mut latest_seen_finality_update = chain.latest_seen_finality_update.lock();

        let head = chain.canonical_head.cached_head();
        let head_block = &head.snapshot.beacon_block;
        let attested_block_root = head_block.message().parent_root();
        let attested_block = chain
            .get_blinded_block(&attested_block_root)?
            .ok_or(Error::FailedConstructingUpdate)?;
        let mut attested_state = chain
            .get_state(&attested_block.state_root(), Some(attested_block.slot()))?
            .ok_or(Error::FailedConstructingUpdate)?;

        let finalized_block_root = attested_state.finalized_checkpoint().root;
        let finalized_block = chain
            .get_blinded_block(&finalized_block_root)?
            .ok_or(Error::FailedConstructingUpdate)?;
        let latest_seen_finality_update_slot = match latest_seen_finality_update.as_ref() {
            Some(update) => update.finalized_header.slot,
            None => Slot::new(0),
        };

        // verify that no other finality_update with a lower or equal
        // finalized_header.slot was already forwarded on the network
        if gossiped_finality_slot <= latest_seen_finality_update_slot {
            return Err(Error::FinalityUpdateAlreadySeen);
        }

        // verify that enough time has passed for the block to have been propagated
        match start_time {
            Some(time) => {
                if seen_timestamp + chain.spec.maximum_gossip_clock_disparity()
                    < time + one_third_slot_duration
                {
                    return Err(Error::TooEarly);
                }
            }
            None => return Err(Error::SigSlotStartIsNone),
        }

        let head_state = &head.snapshot.beacon_state;
        let finality_update = LightClientFinalityUpdate::new(
            &chain.spec,
            head_state,
            head_block,
            &mut attested_state,
            &finalized_block,
        )?;

        // verify that the gossiped finality update is the same as the locally constructed one.
        if finality_update != light_client_finality_update {
            return Err(Error::InvalidLightClientFinalityUpdate);
        }

        *latest_seen_finality_update = Some(light_client_finality_update.clone());

        Ok(Self {
            light_client_finality_update,
            seen_timestamp,
        })
    }
}
