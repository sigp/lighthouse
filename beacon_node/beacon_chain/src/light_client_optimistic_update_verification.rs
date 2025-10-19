use crate::{BeaconChain, BeaconChainTypes};
use derivative::Derivative;
use eth2::types::Hash256;
use slot_clock::SlotClock;
use std::time::Duration;
use strum::AsRefStr;
use types::{LightClientOptimisticUpdate, Slot};

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
    /// Light client optimistic update message does not match the locally constructed one, it has a
    /// different signature slot.
    MismatchedSignatureSlot { local: Slot, observed: Slot },
    /// Light client optimistic update message does not match the locally constructed one, it has a
    /// different block header at the same slot.
    MismatchedAttestedHeader {
        local_attested_header_root: Hash256,
        observed_attested_header_root: Hash256,
        signature_slot: Slot,
    },
    /// Light client optimistic update message does not match the locally constructed one, it has a
    /// different sync aggregate for the same slot and attested header.
    MismatchedSyncAggregate {
        attested_header_root: Hash256,
        signature_slot: Slot,
    },
    /// Signature slot start time is none.
    SigSlotStartIsNone,
    /// Failed to construct a LightClientOptimisticUpdate from state.
    FailedConstructingUpdate,
    /// Unknown block with parent root.
    UnknownBlockParentRoot(Hash256),
    /// Silently ignore this light client optimistic update
    Ignore,
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
            .start_of(rcv_optimistic_update.signature_slot())
            .ok_or(Error::SigSlotStartIsNone)?;
        let one_third_slot_duration = Duration::new(chain.spec.seconds_per_slot / 3, 0);
        if seen_timestamp + chain.spec.maximum_gossip_clock_disparity()
            < start_time + one_third_slot_duration
        {
            return Err(Error::TooEarly);
        }

        if let Some(latest_broadcasted_optimistic_update) = chain
            .light_client_server_cache
            .get_latest_broadcasted_optimistic_update()
        {
            // Ignore the incoming optimistic update if we've already broadcasted it
            if latest_broadcasted_optimistic_update == rcv_optimistic_update {
                return Err(Error::Ignore);
            }

            // Ignore the incoming optimistic update if the latest broadcasted slot
            // is greater than the incoming slot.
            if latest_broadcasted_optimistic_update.get_slot() > rcv_optimistic_update.get_slot() {
                return Err(Error::Ignore);
            }
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

        // Ignore the incoming optimistic update if the latest constructed slot
        // is greater than the incoming slot.
        if latest_optimistic_update.get_slot() > rcv_optimistic_update.get_slot() {
            return Err(Error::Ignore);
        }

        // Verify that the gossiped optimistic update is the same as the locally constructed one.
        if latest_optimistic_update != rcv_optimistic_update {
            let signature_slot = latest_optimistic_update.signature_slot();
            if signature_slot != rcv_optimistic_update.signature_slot() {
                // The locally constructed optimistic update is not up to date, probably
                // because the node has fallen behind and needs to sync.
                if rcv_optimistic_update.signature_slot() > signature_slot {
                    return Err(Error::Ignore);
                }
                return Err(Error::MismatchedSignatureSlot {
                    local: signature_slot,
                    observed: rcv_optimistic_update.signature_slot(),
                });
            }
            let local_attested_header_root = latest_optimistic_update.get_canonical_root();
            let observed_attested_header_root = rcv_optimistic_update.get_canonical_root();
            if local_attested_header_root != observed_attested_header_root {
                return Err(Error::MismatchedAttestedHeader {
                    local_attested_header_root,
                    observed_attested_header_root,
                    signature_slot,
                });
            }
            return Err(Error::MismatchedSyncAggregate {
                attested_header_root: local_attested_header_root,
                signature_slot,
            });
        }

        chain
            .light_client_server_cache
            .set_latest_broadcasted_optimistic_update(rcv_optimistic_update.clone());

        let parent_root = rcv_optimistic_update.get_parent_root();
        Ok(Self {
            light_client_optimistic_update: rcv_optimistic_update,
            parent_root,
            seen_timestamp,
        })
    }
}
