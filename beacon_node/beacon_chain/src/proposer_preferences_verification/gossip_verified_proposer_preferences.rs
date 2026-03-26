use std::sync::Arc;

use crate::{
    BeaconChain, BeaconChainTypes, CanonicalHead,
    proposer_preferences_verification::{
        ProposerPreferencesError, proposer_preference_cache::GossipVerifiedProposerPreferenceCache,
    },
};
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
) -> Result<(), ProposerPreferencesError> {
    let proposal_slot = preferences.proposal_slot;
    let validator_index = preferences.validator_index;
    let current_epoch = current_slot.epoch(E::slots_per_epoch());
    let proposal_epoch = proposal_slot.epoch(E::slots_per_epoch());

    if proposal_epoch != current_epoch && proposal_epoch != current_epoch.saturating_add(1u64) {
        return Err(ProposerPreferencesError::InvalidProposalEpoch { proposal_epoch });
    }

    if proposal_slot <= current_slot {
        return Err(ProposerPreferencesError::ProposalSlotAlreadyPassed {
            proposal_slot,
            current_slot,
        });
    }

    let slot_in_epoch = proposal_slot
        .as_usize()
        .checked_rem(E::slots_per_epoch() as usize)
        .ok_or(ProposerPreferencesError::InvalidProposalSlot {
            validator_index,
            proposal_slot,
        })?;

    let lookahead_index = if proposal_epoch == current_epoch.saturating_add(1u64) {
        E::slots_per_epoch() as usize + slot_in_epoch
    } else {
        slot_in_epoch
    };

    let proposer_lookahead = head_state.proposer_lookahead().map_err(|_| {
        ProposerPreferencesError::InvalidProposalSlot {
            validator_index,
            proposal_slot,
        }
    })?;

    let expected_proposer = proposer_lookahead.get(lookahead_index).ok_or(
        ProposerPreferencesError::InvalidProposalSlot {
            validator_index,
            proposal_slot,
        },
    )?;

    if *expected_proposer != validator_index {
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
    pub spec: &'a ChainSpec,
}

#[derive(Debug, Clone)]
pub struct SignatureVerifiedProposerPreferences {
    pub signed_preferences: Arc<SignedProposerPreferences>,
}

impl SignatureVerifiedProposerPreferences {
    pub fn new<T: BeaconChainTypes>(
        signed_preferences: Arc<SignedProposerPreferences>,
        state: &BeaconState<T::EthSpec>,
        ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, ProposerPreferencesError> {
        proposer_preferences_signature_set(
            state,
            |i| get_pubkey_from_state(state, i),
            &signed_preferences,
            ctx.spec,
        )
        .map_err(|_| ProposerPreferencesError::BadSignature)?
        .verify()
        .then_some(())
        .ok_or(ProposerPreferencesError::BadSignature)?;

        Ok(Self { signed_preferences })
    }
}

#[derive(Debug, Clone)]
pub struct GossipVerifiedProposerPreferences {
    pub signed_preferences: Arc<SignedProposerPreferences>,
}

impl From<SignatureVerifiedProposerPreferences> for GossipVerifiedProposerPreferences {
    fn from(verified: SignatureVerifiedProposerPreferences) -> Self {
        Self {
            signed_preferences: verified.signed_preferences,
        }
    }
}

impl GossipVerifiedProposerPreferences {
    pub fn new<T: BeaconChainTypes>(
        signed_preferences: Arc<SignedProposerPreferences>,
        ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, ProposerPreferencesError> {
        let proposal_slot = signed_preferences.message.proposal_slot;
        let validator_index = signed_preferences.message.validator_index;
        let cached_head = ctx.canonical_head.cached_head();
        let current_slot = cached_head.head_slot();
        let head_state = &cached_head.snapshot.beacon_state;

        if ctx
            .gossip_verified_proposer_preferences_cache
            .get_seen_validator(&proposal_slot, validator_index)
        {
            return Err(ProposerPreferencesError::AlreadySeen {
                validator_index,
                proposal_slot,
            });
        }

        verify_preferences_consistency(&signed_preferences.message, current_slot, head_state)?;

        let signature_verified =
            SignatureVerifiedProposerPreferences::new(signed_preferences, head_state, ctx)?;

        ctx.gossip_verified_proposer_preferences_cache
            .insert_seen_validator(signature_verified.clone());

        let gossip_verified: GossipVerifiedProposerPreferences = signature_verified.into();

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
    use types::{Address, BeaconState, EthSpec, MinimalEthSpec, ProposerPreferences, Slot};

    use super::verify_preferences_consistency;
    use crate::proposer_preferences_verification::ProposerPreferencesError;

    type E = MinimalEthSpec;

    fn make_preferences(proposal_slot: Slot, validator_index: u64) -> ProposerPreferences {
        ProposerPreferences {
            proposal_slot,
            validator_index,
            fee_recipient: Address::ZERO,
            gas_limit: 30_000_000,
        }
    }

    fn state() -> BeaconState<E> {
        BeaconState::new(0, <_>::default(), &E::default_spec())
    }

    #[test]
    fn test_invalid_epoch_too_old() {
        let current_slot = Slot::new(2 * E::slots_per_epoch());
        let prefs = make_preferences(Slot::new(3), 0);

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &state());
        assert!(matches!(
            result,
            Err(ProposerPreferencesError::InvalidProposalEpoch { .. })
        ));
    }

    #[test]
    fn test_invalid_epoch_too_far_ahead() {
        let current_slot = Slot::new(E::slots_per_epoch());
        let prefs = make_preferences(Slot::new(3 * E::slots_per_epoch() + 1), 0);

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &state());
        assert!(matches!(
            result,
            Err(ProposerPreferencesError::InvalidProposalEpoch { .. })
        ));
    }

    #[test]
    fn test_proposal_slot_already_passed() {
        let current_slot = Slot::new(10);
        let prefs = make_preferences(Slot::new(9), 0);

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &state());
        assert!(matches!(
            result,
            Err(ProposerPreferencesError::ProposalSlotAlreadyPassed { .. })
        ));
    }

    #[test]
    fn test_proposal_slot_equal_to_current() {
        let current_slot = Slot::new(10);
        let prefs = make_preferences(Slot::new(10), 0);

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &state());
        assert!(matches!(
            result,
            Err(ProposerPreferencesError::ProposalSlotAlreadyPassed { .. })
        ));
    }

    #[test]
    fn test_valid_epoch_current() {
        let current_slot = Slot::new(E::slots_per_epoch());
        let prefs = make_preferences(Slot::new(E::slots_per_epoch() + 1), 0);

        // Passes epoch/slot checks, fails on state access (no proposer_lookahead in base state)
        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &state());
        assert!(!matches!(
            result,
            Err(ProposerPreferencesError::InvalidProposalEpoch { .. })
        ));
        assert!(!matches!(
            result,
            Err(ProposerPreferencesError::ProposalSlotAlreadyPassed { .. })
        ));
    }

    #[test]
    fn test_valid_epoch_next() {
        let current_slot = Slot::new(E::slots_per_epoch());
        let prefs = make_preferences(Slot::new(2 * E::slots_per_epoch() + 1), 0);

        let result = verify_preferences_consistency::<E>(&prefs, current_slot, &state());
        assert!(!matches!(
            result,
            Err(ProposerPreferencesError::InvalidProposalEpoch { .. })
        ));
        assert!(!matches!(
            result,
            Err(ProposerPreferencesError::ProposalSlotAlreadyPassed { .. })
        ));
    }
}
