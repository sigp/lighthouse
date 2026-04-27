use super::Error;
use crate::beacon_chain::BeaconStore;
use crate::canonical_head::CanonicalHead;
use crate::observed_attesters::ObservedPayloadAttesters;
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, metrics};
use bls::AggregateSignature;
use educe::Educe;
use parking_lot::RwLock;
use safe_arith::SafeArith;
use slot_clock::SlotClock;
use state_processing::per_block_processing::signature_sets::indexed_payload_attestation_signature_set;
use state_processing::state_advance::partial_state_advance;
use std::borrow::Cow;
use types::{ChainSpec, EthSpec, IndexedPayloadAttestation, PTC, PayloadAttestationMessage, Slot};

pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    pub slot_clock: &'a T::SlotClock,
    pub spec: &'a ChainSpec,
    pub observed_payload_attesters: &'a RwLock<ObservedPayloadAttesters<T::EthSpec>>,
    pub canonical_head: &'a CanonicalHead<T>,
    pub validator_pubkey_cache: &'a RwLock<ValidatorPubkeyCache<T>>,
    pub store: &'a BeaconStore<T>,
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

        // Get head state for PTC computation. If the cached head state is too stale
        // (e.g. during liveness failures with many skipped slots), fall back to loading
        // a more recent state from the store and advancing it if necessary.
        let head = ctx.canonical_head.cached_head();
        let head_state = &head.snapshot.beacon_state;

        let message_epoch = slot.epoch(T::EthSpec::slots_per_epoch());
        let state_epoch = head_state.current_epoch();

        // get_ptc can serve epochs in [state_epoch - 1, state_epoch + min_seed_lookahead].
        // If the message epoch is beyond that range, the head state is stale.
        let advanced_state = if message_epoch
            > state_epoch
                .safe_add(ctx.spec.min_seed_lookahead)
                .map_err(BeaconChainError::from)?
        {
            let head_block_root = head.head_block_root();
            let target_slot = message_epoch.start_slot(T::EthSpec::slots_per_epoch());

            let (state_root, mut state) = ctx
                .store
                .get_advanced_hot_state(
                    head_block_root,
                    target_slot,
                    head.snapshot.beacon_state_root(),
                )
                .map_err(BeaconChainError::from)?
                .ok_or(BeaconChainError::MissingBeaconState(
                    head.snapshot.beacon_state_root(),
                ))?;

            if state
                .current_epoch()
                .safe_add(ctx.spec.min_seed_lookahead)
                .map_err(BeaconChainError::from)?
                < message_epoch
            {
                partial_state_advance(&mut state, Some(state_root), target_slot, ctx.spec)
                    .map_err(BeaconChainError::from)?;
            }

            Some(state)
        } else {
            None
        };

        let state = advanced_state.as_ref().unwrap_or(head_state);

        // [REJECT] `validator_index` is within `get_ptc(state, data.slot)`.
        let ptc = state.get_ptc(slot, ctx.spec)?;
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
            let signature_set = indexed_payload_attestation_signature_set(
                state,
                |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
                &indexed_payload_attestation.signature,
                &indexed_payload_attestation,
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
            validator_pubkey_cache: &self.validator_pubkey_cache,
            store: &self.store,
        }
    }

    pub fn verify_payload_attestation_message_for_gossip(
        &self,
        payload_attestation_message: PayloadAttestationMessage,
    ) -> Result<VerifiedPayloadAttestationMessage<T>, Error> {
        metrics::inc_counter(&metrics::PAYLOAD_ATTESTATION_PROCESSING_REQUESTS);
        let _timer = metrics::start_timer(&metrics::PAYLOAD_ATTESTATION_GOSSIP_VERIFICATION_TIMES);

        let ctx = self.payload_attestation_gossip_context();
        VerifiedPayloadAttestationMessage::new(payload_attestation_message, &ctx).inspect(|_| {
            metrics::inc_counter(&metrics::PAYLOAD_ATTESTATION_PROCESSING_SUCCESSES);
        })
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
