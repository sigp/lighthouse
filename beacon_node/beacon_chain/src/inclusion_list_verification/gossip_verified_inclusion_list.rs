use crate::canonical_head::CanonicalHead;
use crate::inclusion_list_store::{InclusionListStore, InsertOutcome};
use crate::inclusion_list_verification::{
    InclusionListVerificationError, verify_inclusion_list_transactions_bounds,
};
use crate::shuffling_cache::{ShufflingCache, with_cached_shuffling};
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, BeaconStore};
use parking_lot::RwLock;
use slot_clock::SlotClock;
use state_processing::builder_deposits_cache::OnboardBuildersCache;
use state_processing::per_block_processing::signature_sets::inclusion_list_signature_set;
use std::borrow::Cow;
use tracing::debug;
use types::{ChainSpec, EthSpec, Hash256, SignedInclusionList, Slot};

pub struct GossipVerificationContext<'a, T: BeaconChainTypes> {
    pub canonical_head: &'a CanonicalHead<T>,
    pub inclusion_list_store: &'a RwLock<InclusionListStore<T::EthSpec>>,
    pub shuffling_cache: &'a RwLock<ShufflingCache<T::EthSpec>>,
    pub validator_pubkey_cache: &'a RwLock<ValidatorPubkeyCache<T>>,
    pub store: &'a BeaconStore<T>,
    pub builder_onboarding_cache: Option<&'a OnboardBuildersCache>,
    pub slot_clock: &'a T::SlotClock,
    pub spec: &'a ChainSpec,
    pub genesis_validators_root: Hash256,
}

/// A `SignedInclusionList` that has been verified for propagation on the gossip network.
#[derive(Debug)]
pub struct GossipVerifiedInclusionList {
    pub signed_inclusion_list: SignedInclusionList,
    pub is_timely: bool,
}

impl GossipVerifiedInclusionList {
    pub fn new<T: BeaconChainTypes>(
        signed_inclusion_list: SignedInclusionList,
        ctx: &GossipVerificationContext<'_, T>,
    ) -> Result<Self, InclusionListVerificationError> {
        let inclusion_list = &signed_inclusion_list.message;
        let slot = inclusion_list.slot;
        let validator_index = inclusion_list.validator_index;
        let dependent_root = inclusion_list.dependent_root;

        // [IGNORE] This is the first or second valid message from this validator.
        if ctx
            .inclusion_list_store
            .read()
            .seen_twice(slot, dependent_root, validator_index)
        {
            return Err(InclusionListVerificationError::AlreadySeenTwice {
                validator_index,
                slot,
                dependent_root,
            });
        }

        // [IGNORE] `slot` is within the `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance.
        verify_propagation_slot_range(ctx.slot_clock, slot, ctx.spec)?;

        // [IGNORE] The size of the inclusion list transactions is non-zero.
        let transactions_size: u64 = inclusion_list
            .transactions
            .iter()
            .map(|tx| tx.len() as u64)
            .sum();
        if transactions_size == 0 {
            return Err(InclusionListVerificationError::EmptyTransactions);
        }

        // [REJECT] The transactions are within the size limit and none of them are empty.
        verify_inclusion_list_transactions_bounds(&inclusion_list.transactions, ctx.spec)
            .map_err(InclusionListVerificationError::InvalidTransactions)?;

        let epoch = slot.epoch(T::EthSpec::slots_per_epoch());
        let lookahead_start_slot = epoch
            .saturating_sub(ctx.spec.min_seed_lookahead)
            .start_slot(T::EthSpec::slots_per_epoch());
        let dependent_slot = lookahead_start_slot.saturating_sub(1_u64);

        let head_block_root = ctx.canonical_head.cached_head().head_block_root();
        let fork_choice_read = ctx.canonical_head.fork_choice_read_lock();

        // [IGNORE] The dependent block has been seen and passes validation.
        let dependent_block = fork_choice_read
            .get_block(&dependent_root)
            .ok_or(InclusionListVerificationError::DependentRootUnknown { dependent_root })?;

        // [REJECT] The dependent block is not after `dependent_slot`.
        if dependent_block.slot > dependent_slot {
            return Err(InclusionListVerificationError::DependentRootTooRecent {
                dependent_root,
                block_slot: dependent_block.slot,
                dependent_slot,
            });
        }

        // [IGNORE] The dependent block is a possible dependent block for `epoch`.
        let has_qualifying_child = fork_choice_read
            .get_children(&dependent_root)
            .iter()
            .any(|child| child.slot > dependent_slot);
        if !has_qualifying_child && dependent_root != head_block_root {
            return Err(InclusionListVerificationError::InvalidDependentRoot { dependent_root });
        }

        drop(fork_choice_read);

        // The checks above confirm `dependent_root` is the shuffling decision block for `epoch`.
        let committee = with_cached_shuffling(
            ctx.canonical_head,
            ctx.shuffling_cache,
            ctx.store,
            ctx.builder_onboarding_cache,
            ctx.spec,
            dependent_root,
            epoch,
            |cached_shuffling, _| {
                cached_shuffling
                    .committee_cache
                    .get_inclusion_list_committee_at_slot(
                        slot,
                        T::EthSpec::inclusion_list_committee_size(),
                    )
                    .map_err(InclusionListVerificationError::from)
            },
        )?;

        // [REJECT] The validator is a member of the inclusion list committee.
        if !committee.contains(&(validator_index as usize)) {
            return Err(InclusionListVerificationError::NotInCommittee {
                validator_index,
                slot,
            });
        }

        {
            // [REJECT] The signature is valid.
            let pubkey_cache = ctx.validator_pubkey_cache.read();
            let signature_set = inclusion_list_signature_set::<T::EthSpec, _>(
                |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
                &signed_inclusion_list,
                ctx.genesis_validators_root,
                ctx.spec,
            )
            .map_err(|_| InclusionListVerificationError::UnknownValidatorIndex(validator_index))?;

            if !signature_set.verify() {
                return Err(InclusionListVerificationError::InvalidSignature);
            }
        }

        let current_slot = ctx
            .slot_clock
            .now()
            .ok_or(InclusionListVerificationError::UnableToReadSlot)?;
        let is_timely = slot == current_slot
            && ctx
                .slot_clock
                .millis_from_current_slot_start()
                .is_some_and(|time_into_slot| time_into_slot < ctx.spec.get_inclusion_list_due());

        Ok(Self {
            signed_inclusion_list,
            is_timely,
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
) -> Result<(), InclusionListVerificationError> {
    let latest_permissible_slot = slot_clock
        .now_with_future_tolerance(spec.maximum_gossip_clock_disparity())
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if message_slot > latest_permissible_slot {
        return Err(InclusionListVerificationError::FutureSlot {
            message_slot,
            latest_permissible_slot,
        });
    }

    let earliest_permissible_slot = slot_clock
        .now_with_past_tolerance(spec.maximum_gossip_clock_disparity())
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if message_slot < earliest_permissible_slot {
        return Err(InclusionListVerificationError::PastSlot {
            message_slot,
            earliest_permissible_slot,
        });
    }

    Ok(())
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn inclusion_list_gossip_verification_context(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            canonical_head: &self.canonical_head,
            inclusion_list_store: &self.inclusion_list_store,
            shuffling_cache: &self.shuffling_cache,
            validator_pubkey_cache: &self.validator_pubkey_cache,
            store: &self.store,
            builder_onboarding_cache: self.builder_onboarding_cache.as_deref(),
            slot_clock: &self.slot_clock,
            spec: &self.spec,
            genesis_validators_root: self.genesis_validators_root,
        }
    }

    pub fn verify_inclusion_list_for_gossip(
        &self,
        signed_inclusion_list: SignedInclusionList,
    ) -> Result<GossipVerifiedInclusionList, InclusionListVerificationError> {
        let slot = signed_inclusion_list.message.slot;
        let validator_index = signed_inclusion_list.message.validator_index;

        let ctx = self.inclusion_list_gossip_verification_context();
        match GossipVerifiedInclusionList::new(signed_inclusion_list, &ctx) {
            Ok(verified) => {
                debug!(
                    %slot,
                    %validator_index,
                    is_timely = verified.is_timely,
                    "Successfully verified gossip inclusion list"
                );

                // TODO(heze): emit the inclusion_list SSE event

                Ok(verified)
            }
            Err(e) => {
                debug!(
                    error = e.to_string(),
                    %slot,
                    %validator_index,
                    "Rejected gossip inclusion list"
                );
                Err(e)
            }
        }
    }

    pub fn import_inclusion_list(
        &self,
        verified_inclusion_list: GossipVerifiedInclusionList,
    ) -> InsertOutcome {
        self.inclusion_list_store
            .write()
            .process_inclusion_list(verified_inclusion_list)
    }
}
