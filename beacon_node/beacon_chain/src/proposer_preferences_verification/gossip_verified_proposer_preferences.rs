use std::sync::Arc;

use crate::{
    BeaconChain, BeaconChainTypes, BeaconStore, CanonicalHead,
    proposer_preferences_verification::{
        ProposerPreferencesError, proposer_preference_cache::GossipVerifiedProposerPreferenceCache,
    },
};
use eth2::types::{EventKind, ForkVersionedResponse};
use slot_clock::SlotClock;
use state_processing::signature_sets::{get_pubkey_from_state, proposer_preferences_signature_set};
use state_processing::state_advance::partial_state_advance;
use tracing::debug;
use types::{ChainSpec, EthSpec, ProposerPreferences, SignedProposerPreferences, Slot};

/// Verify that proposer preferences are consistent with the current chain state
pub(crate) fn verify_preferences_consistency<E: EthSpec>(
    preferences: &ProposerPreferences,
    current_slot: Slot,
    spec: &ChainSpec,
) -> Result<(), ProposerPreferencesError> {
    let proposal_slot = preferences.proposal_slot;
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

    Ok(())
}

pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    pub canonical_head: &'a CanonicalHead<T>,
    pub gossip_verified_proposer_preferences_cache: &'a GossipVerifiedProposerPreferenceCache,
    pub slot_clock: &'a T::SlotClock,
    pub spec: &'a ChainSpec,
    pub store: &'a BeaconStore<T>,
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

        if ctx
            .gossip_verified_proposer_preferences_cache
            .get_seen_validator(&proposal_slot, dependent_root, validator_index)
        {
            return Err(ProposerPreferencesError::AlreadySeen {
                validator_index,
                proposal_slot,
            });
        }

        verify_preferences_consistency::<T::EthSpec>(
            &signed_preferences.message,
            current_slot,
            ctx.spec,
        )?;

        // Get the block at dependent_root from fork choice to verify canonicity and get state_root
        let fork_choice = ctx.canonical_head.fork_choice_read_lock();
        let dependent_block = fork_choice
            .get_block(&dependent_root)
            .ok_or(ProposerPreferencesError::DependentRootUnknown { dependent_root })?;
        let head_root = cached_head.head_block_root();
        if !fork_choice.is_descendant(dependent_root, head_root) {
            return Err(ProposerPreferencesError::DependentRootNotCanonical { dependent_root });
        }
        let dependent_state_root = dependent_block.state_root;
        drop(fork_choice);

        // We need a state at `target_epoch` so we have the correct proposer lookahead.
        let proposal_epoch = proposal_slot.epoch(T::EthSpec::slots_per_epoch());
        let target_epoch = proposal_epoch.saturating_sub(ctx.spec.min_seed_lookahead);
        let target_slot = target_epoch.start_slot(T::EthSpec::slots_per_epoch());

        let (state_root, mut state) = ctx
            .store
            .get_advanced_hot_state(dependent_root, target_slot, dependent_state_root)
            .map_err(crate::BeaconChainError::DBError)?
            .ok_or(ProposerPreferencesError::DependentRootUnknown { dependent_root })?;

        if state.current_epoch() < target_epoch {
            partial_state_advance(&mut state, Some(state_root), target_slot, ctx.spec)
                .map_err(crate::BeaconChainError::StateAdvanceError)?;
        }

        if !state.is_valid_proposal_slot(&signed_preferences.message, ctx.spec)? {
            return Err(ProposerPreferencesError::InvalidProposalSlot {
                validator_index,
                proposal_slot,
            });
        }

        // Verify signature
        proposer_preferences_signature_set(
            &state,
            |i| get_pubkey_from_state(&state, i),
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
            store: &self.store,
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
    use types::{Address, ChainSpec, EthSpec, Hash256, MinimalEthSpec, ProposerPreferences, Slot};

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

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &spec());
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

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &spec());
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

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &spec());
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

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &spec());
        assert!(matches!(
            result,
            Err(ProposerPreferencesError::ProposalSlotAlreadyPassed { .. })
        ));
    }
}
