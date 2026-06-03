use super::Error;
use crate::beacon_chain::BeaconStore;
use crate::canonical_head::CanonicalHead;
use crate::observed_attesters::ObservedPayloadAttesters;
use crate::shuffling_cache::{ShufflingCache, with_cached_shuffling};
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, metrics};
use bls::AggregateSignature;
use educe::Educe;
use eth2::types::{EventKind, ForkVersionedResponse};
use parking_lot::RwLock;
use slot_clock::SlotClock;
use state_processing::per_block_processing::signature_sets::indexed_payload_attestation_signature_set_from_pubkeys;
use std::borrow::Cow;
use types::{
    ChainSpec, EthSpec, Hash256, IndexedPayloadAttestation, PTC, PayloadAttestationMessage, Slot,
};

pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    pub slot_clock: &'a T::SlotClock,
    pub spec: &'a ChainSpec,
    pub observed_payload_attesters: &'a RwLock<ObservedPayloadAttesters<T::EthSpec>>,
    pub canonical_head: &'a CanonicalHead<T>,
    pub shuffling_cache: &'a RwLock<ShufflingCache<T::EthSpec>>,
    pub validator_pubkey_cache: &'a RwLock<ValidatorPubkeyCache<T>>,
    pub store: &'a BeaconStore<T>,
    pub genesis_validators_root: Hash256,
}

/// A `PayloadAttestationMessage` that has been verified for propagation on the gossip network.
#[derive(Educe)]
#[educe(Clone, Debug)]
pub struct VerifiedPayloadAttestationMessage<T: BeaconChainTypes> {
    payload_attestation_message: PayloadAttestationMessage,
    indexed_payload_attestation: IndexedPayloadAttestation<T::EthSpec>,
    ptc: PTC<T::EthSpec>,
}

impl<T: BeaconChainTypes> VerifiedPayloadAttestationMessage<T> {
    pub fn new(
        payload_attestation_message: PayloadAttestationMessage,
        ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, Error> {
        let slot = payload_attestation_message.data.slot;
        let validator_index = payload_attestation_message.validator_index;

        // [IGNORE] `data.slot` is within the `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance.
        verify_propagation_slot_range(ctx.slot_clock, slot, ctx.spec)?;

        // [IGNORE] There has been no other valid payload attestation message for this
        // validator index.
        if ctx
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

        // [IGNORE] `data.beacon_block_root` has been seen
        // [REJECT] `data.beacon_block_root` passes validation.
        //
        // TODO(gloas): These two conditions are conflated. We need a status table to
        // differentiate between:
        // 1. Blocks we haven't seen (IGNORE), and
        // 2. Blocks we've seen that are invalid (REJECT).
        // Presently both cases return IGNORE.
        let beacon_block_root = payload_attestation_message.data.beacon_block_root;
        if ctx
            .canonical_head
            .fork_choice_read_lock()
            .get_block(&beacon_block_root)
            .is_none()
        {
            return Err(Error::UnknownHeadBlock { beacon_block_root });
        }

        let message_epoch = slot.epoch(T::EthSpec::slots_per_epoch());
        let ptc = with_cached_shuffling(
            ctx.canonical_head,
            ctx.shuffling_cache,
            ctx.store,
            ctx.spec,
            beacon_block_root,
            message_epoch,
            |cached_shuffling, _| cached_shuffling.ptc_for_slot(slot),
        )?;

        // [REJECT] `validator_index` is within `get_ptc(state, data.slot)`.
        if !ptc.0.contains(&(validator_index as usize)) {
            return Err(Error::NotInPTC {
                validator_index,
                slot,
            });
        }

        // Build the indexed form for signature verification and downstream fork choice.
        let indexed_payload_attestation = IndexedPayloadAttestation {
            attesting_indices: vec![validator_index]
                .try_into()
                .map_err(|_| Error::UnknownValidatorIndex(validator_index))?,
            data: payload_attestation_message.data.clone(),
            signature: AggregateSignature::from(&payload_attestation_message.signature),
        };

        {
            // [REJECT] The signature is valid with respect to the `validator_index`.
            let pubkey_cache = ctx.validator_pubkey_cache.read();
            let signature_set = indexed_payload_attestation_signature_set_from_pubkeys(
                |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
                &indexed_payload_attestation.signature,
                &indexed_payload_attestation,
                ctx.genesis_validators_root,
                ctx.spec,
            )
            .map_err(|_| Error::UnknownValidatorIndex(validator_index))?;

            if !signature_set.verify() {
                return Err(Error::InvalidSignature);
            }
        }

        // Record that we have received a valid payload attestation message from this
        // validator. Double check with the write lock to handle race conditions.
        if ctx
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
            payload_attestation_message,
            indexed_payload_attestation,
            ptc,
        })
    }

    pub fn payload_attestation_message(&self) -> &PayloadAttestationMessage {
        &self.payload_attestation_message
    }

    pub fn indexed_payload_attestation(&self) -> &IndexedPayloadAttestation<T::EthSpec> {
        &self.indexed_payload_attestation
    }

    pub fn ptc(&self) -> &PTC<T::EthSpec> {
        &self.ptc
    }

    pub fn into_payload_attestation_message(self) -> PayloadAttestationMessage {
        self.payload_attestation_message
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn payload_attestation_gossip_context(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            slot_clock: &self.slot_clock,
            spec: &self.spec,
            observed_payload_attesters: &self.observed_payload_attesters,
            canonical_head: &self.canonical_head,
            shuffling_cache: &self.shuffling_cache,
            validator_pubkey_cache: &self.validator_pubkey_cache,
            store: &self.store,
            genesis_validators_root: self.genesis_validators_root,
        }
    }

    pub fn verify_payload_attestation_message_for_gossip(
        &self,
        payload_attestation_message: PayloadAttestationMessage,
    ) -> Result<VerifiedPayloadAttestationMessage<T>, Error> {
        metrics::inc_counter(&metrics::PAYLOAD_ATTESTATION_PROCESSING_REQUESTS);
        let _timer = metrics::start_timer(&metrics::PAYLOAD_ATTESTATION_GOSSIP_VERIFICATION_TIMES);

        let ctx = self.payload_attestation_gossip_context();
        VerifiedPayloadAttestationMessage::new(payload_attestation_message, &ctx).inspect(
            |verified| {
                metrics::inc_counter(&metrics::PAYLOAD_ATTESTATION_PROCESSING_SUCCESSES);

                if let Some(event_handler) = self.event_handler.as_ref()
                    && event_handler.has_payload_attestation_message_subscribers()
                {
                    let msg = verified.payload_attestation_message();
                    event_handler.register(EventKind::PayloadAttestationMessage(Box::new(
                        ForkVersionedResponse {
                            version: self.spec.fork_name_at_slot::<T::EthSpec>(msg.data.slot),
                            metadata: Default::default(),
                            data: msg.clone(),
                        },
                    )));
                }
            },
        )
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
