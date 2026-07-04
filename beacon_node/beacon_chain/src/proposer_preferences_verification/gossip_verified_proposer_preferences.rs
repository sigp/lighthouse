use std::sync::Arc;

use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BeaconStore, CanonicalHead,
    beacon_proposer_cache::{BeaconProposerCache, with_proposer_cache},
    proposer_preferences_verification::{
        ProposerPreferencesError, proposer_preference_cache::GossipVerifiedProposerPreferenceCache,
    },
    validator_pubkey_cache::ValidatorPubkeyCache,
};
use eth2::types::{EventKind, ForkVersionedResponse};
use parking_lot::{Mutex, RwLock};
use slot_clock::SlotClock;
use tracing::debug;
use types::{ChainSpec, EthSpec, Hash256, ProposerPreferences, SignedProposerPreferences, Slot};

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
    pub beacon_proposer_cache: &'a Mutex<BeaconProposerCache>,
    pub validator_pubkey_cache: &'a RwLock<ValidatorPubkeyCache<T>>,
    pub genesis_validators_root: Hash256,
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

        // Resolve the proposer for `proposal_slot` via the proposer shuffling cache.
        let proposal_epoch = proposal_slot.epoch(T::EthSpec::slots_per_epoch());
        let proposer = with_proposer_cache(
            ctx.beacon_proposer_cache,
            dependent_root,
            proposal_epoch,
            |proposers| proposers.get_slot::<T::EthSpec>(proposal_slot),
            || {
                debug!(
                    ?dependent_root,
                    %proposal_slot,
                    "Proposer shuffling cache miss for proposer preferences verification"
                );

                // Fetch the dependent block's state root from fork choice. The block need not be
                // canonical: preferences for a non-canonical branch are still verifiable, and the
                // dependent state lives in the hot DB.
                let dependent_state_root = ctx
                    .canonical_head
                    .fork_choice_read_lock()
                    .get_block(&dependent_root)
                    .ok_or(ProposerPreferencesError::DependentRootUnknown { dependent_root })?
                    .state_root;

                // Load a state at `target_slot` so it has the correct proposer lookahead.
                let target_slot = proposal_epoch
                    .saturating_sub(ctx.spec.min_seed_lookahead)
                    .start_slot(T::EthSpec::slots_per_epoch());

                let (state_root, state) = ctx
                    .store
                    .get_advanced_hot_state(dependent_root, target_slot, dependent_state_root)
                    .map_err(BeaconChainError::DBError)?
                    .ok_or(ProposerPreferencesError::DependentRootUnknown { dependent_root })?;

                Ok::<_, ProposerPreferencesError>((state_root, state))
            },
            ctx.spec,
        )?;

        if proposer.index as u64 != validator_index {
            return Err(ProposerPreferencesError::InvalidProposalSlot {
                validator_index,
                proposal_slot,
            });
        }

        // Verify the signature using the proposer's pubkey from the validator pubkey cache
        let signature_is_valid = {
            let pubkey_cache = ctx.validator_pubkey_cache.read();
            let pubkey = pubkey_cache
                .get(validator_index as usize)
                .ok_or(ProposerPreferencesError::BadSignature)?;
            signed_preferences.verify_signature::<T::EthSpec>(
                pubkey,
                &proposer.fork,
                ctx.genesis_validators_root,
                ctx.spec,
            )
        };
        if !signature_is_valid {
            return Err(ProposerPreferencesError::BadSignature);
        }

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
            beacon_proposer_cache: &self.beacon_proposer_cache,
            validator_pubkey_cache: &self.validator_pubkey_cache,
            genesis_validators_root: self.genesis_validators_root,
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
