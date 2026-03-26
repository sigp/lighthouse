use std::sync::Arc;

use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, CanonicalHead,
    proposer_preferences_verification::{
        ProposerPreferencesError, proposer_preference_cache::GossipVerifiedProposerPreferenceCache,
    },
};
use state_processing::signature_sets::{get_pubkey_from_state, proposer_preferences_signature_set};
use tracing::{Span, debug};
use types::{BeaconState, ChainSpec, EthSpec, SignedProposerPreferences};

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
            &ctx.spec,
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
        let current_slot = ctx.canonical_head.cached_head().head_slot();
        let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());
        let proposal_epoch = proposal_slot.epoch(T::EthSpec::slots_per_epoch());

        if ctx
            .gossip_verified_proposer_preferences_cache
            .get_seen_validator(&proposal_slot, validator_index)
        {
            return Err(ProposerPreferencesError::AlreadySeen {
                validator_index,
                proposal_slot,
            });
        }

        if proposal_epoch != current_epoch && proposal_epoch != current_epoch.saturating_add(1u64) {
            return Err(ProposerPreferencesError::InvalidProposalSlotEpoch { proposal_slot });
        }

        if proposal_slot <= current_slot {
            return Err(ProposerPreferencesError::ProposalSlotAlreadyPassed {
                proposal_slot,
                current_slot,
            });
        }

        let slot_in_epoch = proposal_slot
            .as_usize()
            .checked_rem(T::EthSpec::slots_per_epoch() as usize)
            .ok_or(ProposerPreferencesError::InvalidProposalSlot {
                validator_index,
                proposal_slot,
            })?;

        let lookahead_index = if proposal_epoch == current_epoch.saturating_add(1u64) {
            T::EthSpec::slots_per_epoch() as usize + slot_in_epoch
        } else {
            slot_in_epoch
        };

        let head_state = &ctx.canonical_head.cached_head().snapshot.beacon_state;

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

    pub async fn verify_proposer_preferences_for_gossip(
        self: &Arc<Self>,
        signed_preferences: Arc<SignedProposerPreferences>,
    ) -> Result<GossipVerifiedProposerPreferences, ProposerPreferencesError> {
        let chain = self.clone();
        let span = Span::current();
        self.task_executor
            .clone()
            .spawn_blocking_handle(
                move || {
                    let _guard = span.enter();
                    let proposal_slot = signed_preferences.message.proposal_slot;
                    let validator_index = signed_preferences.message.validator_index;

                    let ctx = chain.proposer_preferences_gossip_verification_context();
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
                },
                "gossip_proposer_preferences_verification_handle",
            )
            .ok_or(BeaconChainError::RuntimeShutdown)?
            .await
            .map_err(BeaconChainError::TokioJoin)?
    }
}
