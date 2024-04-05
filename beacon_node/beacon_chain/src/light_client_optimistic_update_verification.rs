use crate::{BeaconChain, BeaconChainTypes};
use derivative::Derivative;
use eth2::types::Hash256;
use slot_clock::SlotClock;
use std::time::Duration;
use strum::AsRefStr;
use types::LightClientOptimisticUpdate;

/// Returned when a light client optimistic update was not successfully verified. It might not have been verified for
/// two reasons:
///
/// - The light client optimistic message is malformed or inappropriate for the context (indicated by all variants
///   other than `BeaconChainError`).
/// - The application encountered an internal error whilst attempting to determine validity
///   (the `BeaconChainError` variant)
#[derive(Debug, AsRefStr)]
pub enum Error {
    /// The light client optimistic message was received is prior to one-third of slot duration passage. (with
    /// respect to the gossip clock disparity and slot clock duration).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    TooEarly,
    /// Light client optimistic update message does not match the locally constructed one.
    InvalidLightClientOptimisticUpdate,
    /// Signature slot start time is none.
    SigSlotStartIsNone,
    /// Failed to construct a LightClientOptimisticUpdate from state.
    FailedConstructingUpdate,
    /// Unknown block with parent root.
    UnknownBlockParentRoot(Hash256),
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
            .start_of(*rcv_optimistic_update.signature_slot())
            .ok_or(Error::SigSlotStartIsNone)?;
        let one_third_slot_duration = Duration::new(chain.spec.seconds_per_slot / 3, 0);
        if seen_timestamp + chain.spec.maximum_gossip_clock_disparity()
            < start_time + one_third_slot_duration
        {
            return Err(Error::TooEarly);
        }

        let head = chain.canonical_head.cached_head();
        let head_block = &head.snapshot.beacon_block;
        // check if we can process the optimistic update immediately
        // otherwise queue
        let canonical_root = rcv_optimistic_update.get_canonical_root();

        if canonical_root != head_block.message().parent_root() {
            return Err(Error::UnknownBlockParentRoot(canonical_root));
        }

        let latest_optimistic_update = chain
            .light_client_server_cache
            .get_latest_optimistic_update()
            .ok_or(Error::FailedConstructingUpdate)?;

        // verify that the gossiped optimistic update is the same as the locally constructed one.
        if latest_optimistic_update != rcv_optimistic_update {
            return Err(Error::InvalidLightClientOptimisticUpdate);
        }

        let parent_root = rcv_optimistic_update.get_parent_root();
        Ok(Self {
            light_client_optimistic_update: rcv_optimistic_update,
            parent_root,
            seen_timestamp,
        })
    }
}
