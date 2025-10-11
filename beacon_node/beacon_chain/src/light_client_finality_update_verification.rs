use crate::{BeaconChain, BeaconChainTypes};
use derivative::Derivative;
use slot_clock::SlotClock;
use std::time::Duration;
use strum::AsRefStr;
use types::{Hash256, LightClientFinalityUpdate, Slot};

/// Returned when a light client finality update was not successfully verified. It might not have been verified for
/// two reasons:
///
/// - The light client finality message is malformed or inappropriate for the context (indicated by all variants
///   other than `BeaconChainError`).
/// - The application encountered an internal error whilst attempting to determine validity
///   (the `BeaconChainError` variant)
#[derive(Debug, AsRefStr)]
pub enum Error {
    /// The light client finality message was received is prior to one-third of slot duration passage. (with
    /// respect to the gossip clock disparity and slot clock duration).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    TooEarly,
    /// Light client finalized update message does not match the locally constructed one, it has a
    /// different signature slot.
    MismatchedSignatureSlot { local: Slot, observed: Slot },
    /// Light client finalized update message does not match the locally constructed one, it has a
    /// different finalized block header for the same signature slot.
    MismatchedFinalizedHeader {
        local_finalized_header_root: Hash256,
        observed_finalized_header_root: Hash256,
        signature_slot: Slot,
    },
    /// Light client finalized update message does not match the locally constructed one, it has a
    /// different attested block header for the same signature slot and finalized header.
    MismatchedAttestedHeader {
        local_attested_header_root: Hash256,
        observed_attested_header_root: Hash256,
        finalized_header_root: Hash256,
        signature_slot: Slot,
    },
    /// Light client finalized update message does not match the locally constructed one, it has a
    /// different proof or sync aggregate for the same slot, attested header and finalized header.
    MismatchedProofOrSyncAggregate {
        attested_header_root: Hash256,
        finalized_header_root: Hash256,
        signature_slot: Slot,
    },
    /// Signature slot start time is none.
    SigSlotStartIsNone,
    /// Failed to construct a LightClientFinalityUpdate from state.
    FailedConstructingUpdate,
    /// Silently ignore this light client finality update
    Ignore,
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
        rcv_finality_update: LightClientFinalityUpdate<T::EthSpec>,
        chain: &BeaconChain<T>,
        seen_timestamp: Duration,
    ) -> Result<Self, Error> {
        // verify that enough time has passed for the block to have been propagated
        let start_time = chain
            .slot_clock
            .start_of(rcv_finality_update.signature_slot())
            .ok_or(Error::SigSlotStartIsNone)?;
        let one_third_slot_duration = Duration::new(chain.spec.seconds_per_slot / 3, 0);
        if seen_timestamp + chain.spec.maximum_gossip_clock_disparity()
            < start_time + one_third_slot_duration
        {
            return Err(Error::TooEarly);
        }

        if let Some(latest_broadcasted_finality_update) = chain
            .light_client_server_cache
            .get_latest_broadcasted_finality_update()
        {
            // Ignore the incoming finality update if we've already broadcasted it
            if latest_broadcasted_finality_update == rcv_finality_update {
                return Err(Error::Ignore);
            }

            // Ignore the incoming finality update if the latest broadcasted attested header slot
            // is greater than the incoming attested header slot.
            if latest_broadcasted_finality_update.get_attested_header_slot()
                > rcv_finality_update.get_attested_header_slot()
            {
                return Err(Error::Ignore);
            }
        }

        let latest_finality_update = chain
            .light_client_server_cache
            .get_latest_finality_update()
            .ok_or(Error::FailedConstructingUpdate)?;

        // Ignore the incoming finality update if the latest constructed attested header slot
        // is greater than the incoming attested header slot.
        if latest_finality_update.get_attested_header_slot()
            > rcv_finality_update.get_attested_header_slot()
        {
            return Err(Error::Ignore);
        }

        // Verify that the gossiped finality update is the same as the locally constructed one.
        if latest_finality_update != rcv_finality_update {
            let signature_slot = latest_finality_update.signature_slot();

            if signature_slot != rcv_finality_update.signature_slot() {
                // The locally constructed finality update is not up to date, probably
                // because the node has fallen behind and needs to sync.
                if rcv_finality_update.signature_slot() > signature_slot {
                    return Err(Error::Ignore);
                }
                return Err(Error::MismatchedSignatureSlot {
                    local: signature_slot,
                    observed: rcv_finality_update.signature_slot(),
                });
            }
            let local_finalized_header_root = latest_finality_update.get_finalized_header_root();
            let observed_finalized_header_root = rcv_finality_update.get_finalized_header_root();
            if local_finalized_header_root != observed_finalized_header_root {
                return Err(Error::MismatchedFinalizedHeader {
                    local_finalized_header_root,
                    observed_finalized_header_root,
                    signature_slot,
                });
            }
            let local_attested_header_root = latest_finality_update.get_attested_header_root();
            let observed_attested_header_root = rcv_finality_update.get_attested_header_root();
            if local_attested_header_root != observed_attested_header_root {
                return Err(Error::MismatchedAttestedHeader {
                    local_attested_header_root,
                    observed_attested_header_root,
                    finalized_header_root: local_finalized_header_root,
                    signature_slot,
                });
            }
            return Err(Error::MismatchedProofOrSyncAggregate {
                attested_header_root: local_attested_header_root,
                finalized_header_root: local_finalized_header_root,
                signature_slot,
            });
        }

        chain
            .light_client_server_cache
            .set_latest_broadcasted_finality_update(rcv_finality_update.clone());

        Ok(Self {
            light_client_finality_update: rcv_finality_update,
            seen_timestamp,
        })
    }
}
