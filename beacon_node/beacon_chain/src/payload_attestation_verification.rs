//! Provides verification for `PayloadAttestationMessage` received from the gossip network.
//!
//! Similar to `crate::attestation_verification`, we try to avoid doing duplicate verification
//! work as a payload attestation message passes through different stages of verification.
//!
//! ```ignore
//!      types::PayloadAttestationMessage
//!              |
//!              ▼
//!      IndexedPayloadAttestationMessage
//!              |
//!              ▼
//!      VerifiedPayloadAttestationMessage
//! ```

use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use bls::AggregateSignature;
use slot_clock::SlotClock;
use state_processing::per_block_processing::signature_sets::indexed_payload_attestation_signature_set;
use std::borrow::Cow;
use strum::AsRefStr;
use types::{
    BeaconState, BeaconStateError, ChainSpec, EthSpec, Hash256, IndexedPayloadAttestation, PTC,
    PayloadAttestationMessage, Slot,
};

/// Returned when a payload attestation message was not successfully verified. It might not have
/// been verified for two reasons:
///
/// - The message is malformed or inappropriate for the context (indicated by all variants
///   other than `BeaconChainError`).
/// - The application encountered an internal error whilst attempting to determine validity
///   (the `BeaconChainError` variant)
#[derive(Debug, AsRefStr)]
pub enum Error {
    /// The payload attestation message is from a slot that is later than the current slot
    /// (with respect to the gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    FutureSlot {
        message_slot: Slot,
        latest_permissible_slot: Slot,
    },
    /// The payload attestation message is from a slot that is prior to the earliest
    /// permissible slot (with respect to the gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    PastSlot {
        message_slot: Slot,
        earliest_permissible_slot: Slot,
    },
    /// We have already observed a valid payload attestation message from this validator
    /// for this slot.
    ///
    /// ## Peer scoring
    ///
    /// The peer is not necessarily faulty.
    PriorPayloadAttestationMessageKnown { validator_index: u64, slot: Slot },
    /// The beacon block referenced by the payload attestation message is not known.
    ///
    /// ## Peer scoring
    ///
    /// The attestation points to a block we have not yet imported. It's unclear if the
    /// attestation is valid or not.
    UnknownHeadBlock { beacon_block_root: Hash256 },
    /// The validator index is not a member of the PTC for this slot.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    NotInPTC { validator_index: u64, slot: Slot },
    /// The validator index is unknown.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    UnknownValidatorIndex(u64),
    /// The signature on the payload attestation message is invalid.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidSignature,
    /// There was an error whilst processing the payload attestation message. It is not known
    /// if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this message due to an internal error. It's unclear if the
    /// message is valid.
    BeaconChainError(Box<BeaconChainError>),
    /// An error reading beacon state.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this message due to an internal error.
    BeaconStateError(BeaconStateError),
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChainError(Box::new(e))
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconStateError(e)
    }
}

/// Wraps a `PayloadAttestationMessage` that has passed early and middle checks but has *not*
/// undergone signature verification.
struct IndexedPayloadAttestationMessage<T: BeaconChainTypes> {
    payload_attestation_message: PayloadAttestationMessage,
    indexed_payload_attestation: IndexedPayloadAttestation<T::EthSpec>,
    ptc: PTC<T::EthSpec>,
}

/// Wraps a `PayloadAttestationMessage` that has been fully verified for propagation on the
/// gossip network.
#[derive(Clone, Debug)]
pub struct VerifiedPayloadAttestationMessage<E: EthSpec> {
    payload_attestation_message: PayloadAttestationMessage,
    indexed_payload_attestation: IndexedPayloadAttestation<E>,
    ptc: PTC<E>,
}

impl<T: BeaconChainTypes> IndexedPayloadAttestationMessage<T> {
    fn verify_early_checks(
        payload_attestation_message: &PayloadAttestationMessage,
        chain: &BeaconChain<T>,
    ) -> Result<(), Error> {
        let slot = payload_attestation_message.data.slot;
        let validator_index = payload_attestation_message.validator_index;

        verify_propagation_slot_range(&chain.slot_clock, slot, &chain.spec)?;

        if chain
            .observed_payload_attesters
            .read()
            .validator_has_been_observed(slot, validator_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorPayloadAttestationMessageKnown {
                validator_index,
                slot,
            });
        }

        let beacon_block_root = payload_attestation_message.data.beacon_block_root;
        if chain
            .canonical_head
            .fork_choice_read_lock()
            .get_block(&beacon_block_root)
            .is_none()
        {
            return Err(Error::UnknownHeadBlock { beacon_block_root });
        }

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn verify_middle_checks(
        payload_attestation_message: &PayloadAttestationMessage,
        chain: &BeaconChain<T>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<(IndexedPayloadAttestation<T::EthSpec>, PTC<T::EthSpec>), Error> {
        let slot = payload_attestation_message.data.slot;
        let validator_index = payload_attestation_message.validator_index;

        let ptc = state.get_ptc(slot, &chain.spec)?;
        if !ptc.0.contains(&(validator_index as usize)) {
            return Err(Error::NotInPTC {
                validator_index,
                slot,
            });
        }

        let indexed_payload_attestation = IndexedPayloadAttestation {
            attesting_indices: vec![validator_index]
                .try_into()
                .map_err(|_| Error::UnknownValidatorIndex(validator_index))?,
            data: payload_attestation_message.data.clone(),
            signature: AggregateSignature::from(&payload_attestation_message.signature),
        };

        Ok((indexed_payload_attestation, ptc))
    }

    /// Runs early and middle checks, producing an intermediate verified form.
    fn verify(
        payload_attestation_message: PayloadAttestationMessage,
        chain: &BeaconChain<T>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<Self, Error> {
        Self::verify_early_checks(&payload_attestation_message, chain)?;
        let (indexed_payload_attestation, ptc) =
            Self::verify_middle_checks(&payload_attestation_message, chain, state)?;

        Ok(Self {
            payload_attestation_message,
            indexed_payload_attestation,
            ptc,
        })
    }
}

impl<E: EthSpec> VerifiedPayloadAttestationMessage<E> {
    /// Returns `Ok(Self)` if the `payload_attestation_message` is valid to be (re)published on
    /// the gossip network.
    pub fn verify<T: BeaconChainTypes<EthSpec = E>>(
        payload_attestation_message: PayloadAttestationMessage,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        // TODO(manas): i think we can have a shuffling cache. but this an interim solution
        // can be discussed.
        let head_snapshot = chain.head_snapshot();
        let head_state = &head_snapshot.beacon_state;

        let indexed = IndexedPayloadAttestationMessage::verify(
            payload_attestation_message,
            chain,
            head_state,
        )?;

        Self::from_indexed(indexed, chain, head_state)
    }

    fn from_indexed<T: BeaconChainTypes<EthSpec = E>>(
        indexed: IndexedPayloadAttestationMessage<T>,
        chain: &BeaconChain<T>,
        state: &BeaconState<E>,
    ) -> Result<Self, Error> {
        let slot = indexed.payload_attestation_message.data.slot;
        let validator_index = indexed.payload_attestation_message.validator_index;

        let pubkey_cache = chain.validator_pubkey_cache.read();

        let signature_set = indexed_payload_attestation_signature_set(
            state,
            |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
            &indexed.indexed_payload_attestation.signature,
            &indexed.indexed_payload_attestation,
            &chain.spec,
        )
        .map_err(|_| Error::UnknownValidatorIndex(validator_index))?;

        if !signature_set.verify() {
            return Err(Error::InvalidSignature);
        }

        // Now that the message has been fully verified, store that we have received a valid
        // payload attestation message from this validator.
        //
        // Double check with the write lock to handle race conditions.
        if chain
            .observed_payload_attesters
            .write()
            .observe_validator(slot, validator_index as usize, ())
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorPayloadAttestationMessageKnown {
                validator_index,
                slot,
            });
        }

        Ok(Self {
            payload_attestation_message: indexed.payload_attestation_message,
            indexed_payload_attestation: indexed.indexed_payload_attestation,
            ptc: indexed.ptc,
        })
    }

    pub fn payload_attestation_message(&self) -> &PayloadAttestationMessage {
        &self.payload_attestation_message
    }

    pub fn indexed_payload_attestation(&self) -> &IndexedPayloadAttestation<E> {
        &self.indexed_payload_attestation
    }

    pub fn ptc(&self) -> &PTC<E> {
        &self.ptc
    }

    pub fn into_payload_attestation_message(self) -> PayloadAttestationMessage {
        self.payload_attestation_message
    }
}

/// Verify that the `slot` is within the acceptable gossip propagation range, with reference
/// to the current slot of the clock.
///
/// Accounts for `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
fn verify_propagation_slot_range<S: SlotClock>(
    slot_clock: &S,
    message_slot: Slot,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let latest_permissible_slot = slot_clock
        .now_with_future_tolerance(spec.maximum_gossip_clock_disparity())
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if message_slot > latest_permissible_slot {
        return Err(Error::FutureSlot {
            message_slot,
            latest_permissible_slot,
        });
    }

    let earliest_permissible_slot = slot_clock
        .now_with_past_tolerance(spec.maximum_gossip_clock_disparity())
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if message_slot < earliest_permissible_slot {
        return Err(Error::PastSlot {
            message_slot,
            earliest_permissible_slot,
        });
    }

    Ok(())
}
