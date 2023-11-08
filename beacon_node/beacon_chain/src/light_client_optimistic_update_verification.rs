use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use derivative::Derivative;
use eth2::types::Hash256;
use slot_clock::SlotClock;
use std::time::Duration;
use strum::AsRefStr;
use types::{light_client_update::Error as LightClientUpdateError, LightClientOptimisticUpdate};

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
    /// Unknown block with parent root.
    UnknownBlockParentRoot(Hash256),
    /// Beacon chain error occurred.
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
    pub parent_root: Hash256,
    seen_timestamp: Duration,
}

impl<T: BeaconChainTypes> VerifiedLightClientOptimisticUpdate<T> {
    /// Returns `Ok(Self)` if the `light_client_optimistic_update` is valid to be (re)published on the gossip
    /// network.
    pub fn verify(
        rcv_optimistic_update: LightClientOptimisticUpdate<T::EthSpec>,
        chain: &BeaconChain<T>,
        seen_timestamp: Duration,
    ) -> Result<Self, Error> {
        // verify that enough time has passed for the block to have been propagated
        let start_time = chain
            .slot_clock
            .start_of(rcv_optimistic_update.signature_slot);
        let one_third_slot_duration = Duration::new(chain.spec.seconds_per_slot / 3, 0);
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

        let latest_optimistic_update = chain
            .lightclient_server_cache
            .get_latest_optimistic_update()
            .ok_or(Error::FailedConstructingUpdate)?;

        // verify that the gossiped optimistic update is the same as the locally constructed one.
        if latest_optimistic_update != rcv_optimistic_update {
            return Err(Error::InvalidLightClientOptimisticUpdate);
        }

        let parent_root = rcv_optimistic_update.attested_header.beacon.parent_root;
        Ok(Self {
            light_client_optimistic_update: rcv_optimistic_update,
            // TODO: why is the parent_root necessary here?
            parent_root,
            seen_timestamp,
        })
    }
}
