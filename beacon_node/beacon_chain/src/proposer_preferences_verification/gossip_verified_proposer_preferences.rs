use std::sync::Arc;

use crate::{
    BeaconChain, BeaconChainTypes, CanonicalHead,
    proposer_preferences_verification::{
        ProposerPreferencesError, proposer_preference_cache::GossipVerifiedProposerPreferenceCache,
    },
};
use eth2::types::{EventKind, ForkVersionedResponse};
use slot_clock::SlotClock;
use state_processing::signature_sets::{get_pubkey_from_state, proposer_preferences_signature_set};
use tracing::debug;
use types::{
    BeaconState, ChainSpec, EthSpec, ProposerPreferences, SignedProposerPreferences, Slot,
};

/// Verify that proposer preferences are consistent with the current chain state
pub(crate) fn verify_preferences_consistency<E: EthSpec>(
    preferences: &ProposerPreferences,
    current_slot: Slot,
    head_state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), ProposerPreferencesError> {
    let proposal_slot = preferences.proposal_slot;
    let validator_index = preferences.validator_index;
    let current_epoch = current_slot.epoch(E::slots_per_epoch());
    let proposal_epoch = proposal_slot.epoch(E::slots_per_epoch());

    if proposal_epoch < current_epoch
        || proposal_epoch > current_epoch.saturating_add(spec.min_seed_lookahead)
    {
        return Err(ProposerPreferencesError::InvalidProposalEpoch { proposal_epoch });
    }

    if proposal_slot <= current_slot {
        return Err(ProposerPreferencesError::ProposalSlotAlreadyPassed {
            proposal_slot,
            current_slot,
        });
    }

    if !head_state.is_valid_proposal_slot(preferences, spec)? {
        return Err(ProposerPreferencesError::InvalidProposalSlot {
            validator_index,
            proposal_slot,
        });
    }

    Ok(())
}

pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    pub canonical_head: &'a CanonicalHead<T>,
    pub gossip_verified_proposer_preferences_cache: &'a GossipVerifiedProposerPreferenceCache,
    pub slot_clock: &'a T::SlotClock,
    pub spec: &'a ChainSpec,
}

/// A wrapper around `SignedProposerPreferences` that has been verified for gossip propagation.
#[derive(Debug, Clone)]
pub struct GossipVerifiedProposerPreferences {
    pub signed_preferences: Arc<SignedProposerPreferences>,
}

impl GossipVerifiedProposerPreferences {
    pub fn new<T: BeaconChainTypes>(
        signed_preferences: Arc<SignedProposerPreferences>,
        ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, ProposerPreferencesError> {
        let proposal_slot = signed_preferences.message.proposal_slot;
        let dependent_root = signed_preferences.message.dependent_root;
        let validator_index = signed_preferences.message.validator_index;
        let cached_head = ctx.canonical_head.cached_head();
        let current_slot = ctx
            .slot_clock
            .now()
            .ok_or(ProposerPreferencesError::UnableToReadSlot)?;
        let head_state = &cached_head.snapshot.beacon_state;

        if ctx
            .gossip_verified_proposer_preferences_cache
            .get_seen_validator(&proposal_slot, dependent_root, validator_index)
        {
            return Err(ProposerPreferencesError::AlreadySeen {
                validator_index,
                proposal_slot,
            });
        }

        verify_preferences_consistency(
            &signed_preferences.message,
            current_slot,
            head_state,
            ctx.spec,
        )?;

        // Verify signature
        proposer_preferences_signature_set(
            head_state,
            |i| get_pubkey_from_state(head_state, i),
            &signed_preferences,
            ctx.spec,
        )
        .map_err(|_| ProposerPreferencesError::BadSignature)?
        .verify()
        .then_some(())
        .ok_or(ProposerPreferencesError::BadSignature)?;

        let gossip_verified = GossipVerifiedProposerPreferences { signed_preferences };

        ctx.gossip_verified_proposer_preferences_cache
            .insert_seen_validator(&gossip_verified);

        ctx.gossip_verified_proposer_preferences_cache
            .insert_preferences(gossip_verified.clone());

        Ok(gossip_verified)
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn proposer_preferences_gossip_verification_context(
        &self,
    ) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            canonical_head: &self.canonical_head,
            gossip_verified_proposer_preferences_cache: &self
                .gossip_verified_proposer_preferences_cache,
            slot_clock: &self.slot_clock,
            spec: &self.spec,
        }
    }

    pub fn verify_proposer_preferences_for_gossip(
        &self,
        signed_preferences: Arc<SignedProposerPreferences>,
    ) -> Result<GossipVerifiedProposerPreferences, ProposerPreferencesError> {
        let proposal_slot = signed_preferences.message.proposal_slot;
        let validator_index = signed_preferences.message.validator_index;

        let ctx = self.proposer_preferences_gossip_verification_context();
        match GossipVerifiedProposerPreferences::new(signed_preferences, &ctx) {
            Ok(verified) => {
                debug!(
                    %proposal_slot,
                    %validator_index,
                    "Successfully verified gossip proposer preferences"
                );

                if let Some(event_handler) = self.event_handler.as_ref()
                    && event_handler.has_proposer_preferences_subscribers()
                {
                    event_handler.register(EventKind::ProposerPreferences(Box::new(
                        ForkVersionedResponse {
                            version: self.spec.fork_name_at_slot::<T::EthSpec>(proposal_slot),
                            metadata: Default::default(),
                            data: (*verified.signed_preferences).clone(),
                        },
                    )));
                }

                Ok(verified)
            }
            Err(e) => {
                debug!(
                    error = e.to_string(),
                    %proposal_slot,
                    %validator_index,
                    "Rejected gossip proposer preferences"
                );
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use types::{
        Address, BeaconState, ChainSpec, EthSpec, Hash256, MinimalEthSpec, ProposerPreferences,
        Slot,
    };

    use super::verify_preferences_consistency;
    use crate::proposer_preferences_verification::ProposerPreferencesError;
    use crate::test_utils::{fork_name_from_env, test_spec};

    type E = MinimalEthSpec;

    fn make_preferences(proposal_slot: Slot, validator_index: u64) -> ProposerPreferences {
        ProposerPreferences {
            dependent_root: Hash256::ZERO,
            proposal_slot,
            validator_index,
            fee_recipient: Address::ZERO,
            target_gas_limit: 30_000_000,
        }
    }

    fn state() -> BeaconState<E> {
        let spec = spec();
        BeaconState::new(0, <_>::default(), &spec)
    }

    fn spec() -> ChainSpec {
        test_spec::<E>()
    }

    #[test]
    fn test_invalid_epoch_too_old() {
        if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
            return;
        }
        let current_slot = Slot::new(2 * E::slots_per_epoch());
        let prefs = make_preferences(Slot::new(3), 0);

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &state(), &spec());
        assert!(matches!(
            result,
            Err(ProposerPreferencesError::InvalidProposalEpoch { .. })
        ));
    }

    #[test]
    fn test_invalid_epoch_too_far_ahead() {
        if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
            return;
        }
        let current_slot = Slot::new(E::slots_per_epoch());
        let prefs = make_preferences(Slot::new(3 * E::slots_per_epoch() + 1), 0);

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &state(), &spec());
        assert!(matches!(
            result,
            Err(ProposerPreferencesError::InvalidProposalEpoch { .. })
        ));
    }

    #[test]
    fn test_proposal_slot_already_passed() {
        if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
            return;
        }
        let current_slot = Slot::new(10);
        let prefs = make_preferences(Slot::new(9), 0);

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &state(), &spec());
        assert!(matches!(
            result,
            Err(ProposerPreferencesError::ProposalSlotAlreadyPassed { .. })
        ));
    }

    #[test]
    fn test_proposal_slot_equal_to_current() {
        if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
            return;
        }
        let current_slot = Slot::new(10);
        let prefs = make_preferences(Slot::new(10), 0);

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &state(), &spec());
        assert!(matches!(
            result,
            Err(ProposerPreferencesError::ProposalSlotAlreadyPassed { .. })
        ));
    }
}
