//! Provides verification for the following sync committee:
//!
//! - "Unaggregated" `SyncCommitteeSignature` received from either gossip or the HTTP API.
//! - "Aggregated" `SignedContributionAndProof` received from gossip or the HTTP API.
//!
//! For clarity, we define:
//!
//! - Unaggregated: a `SyncCommitteeSignature` object.
//! - Aggregated: a `SignedContributionAndProof` which has zero or more signatures.
//!   - Note: "zero or more" may soon change to "one or more".
//!
//! Similar to the `crate::block_verification` module, we try to avoid doing duplicate verification
//! work as a sync committee signature passes through different stages of verification. We represent these
//! different stages of verification with wrapper types. These wrapper-types flow in a particular
//! pattern:
//!
//! ```ignore
//!      types::SyncCommitteeSignature              types::SignedContributionAndProof
//!              |                                    |
//!              ▼                                    ▼
//!  VerifiedUnaggregatedSyncContribution     VerifiedAggregatedSyncContribution
//!              |                                    |
//!              -------------------------------------
//!                                |
//!                                ▼
//!                  impl SignatureVerifiedSyncContribution
//! ```

use std::borrow::Cow;
use std::collections::HashMap;

use strum::AsRefStr;

use bls::verify_signature_sets;
use eth2::lighthouse_vc::types::attestation::SlotData;
use proto_array::Block as ProtoBlock;
use safe_arith::ArithError;
use safe_arith::SafeArith;
use slot_clock::SlotClock;
use state_processing::per_block_processing::errors::SyncSignatureValidationError;
use state_processing::signature_sets::{
    signed_sync_aggregate_selection_proof_signature_set, signed_sync_aggregate_signature_set,
    sync_committee_contribution_signature_set_from_pubkeys,
};
use tree_hash::TreeHash;
use types::consts::altair::SYNC_COMMITTEE_SUBNET_COUNT;
use types::{
    sync_committee_contribution::Error as ContributionError, AggregateSignature, EthSpec, Hash256,
    SignedContributionAndProof, Slot, SyncCommitteeContribution, SyncCommitteeSignature,
    SyncSelectionProof, SyncSubnetId, Unsigned,
};

use crate::{
    beacon_chain::{
        HEAD_LOCK_TIMEOUT, MAXIMUM_GOSSIP_CLOCK_DISPARITY, VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT,
    },
    metrics,
    observed_aggregates::ObserveOutcome,
    observed_attesters::Error as ObservedAttestersError,
    BeaconChain, BeaconChainError, BeaconChainTypes,
};

/// Returned when a sync committee contribution was not successfully verified. It might not have been verified for
/// two reasons:
///
/// - The attestation is malformed or inappropriate for the context (indicated by all variants
///   other than `BeaconChainError`).
/// - The application encountered an internal error whilst attempting to determine validity
///   (the `BeaconChainError` variant)
#[derive(Debug, AsRefStr)]
pub enum Error {
    /// The attestation is from a slot that is later than the current slot (with respect to the
    /// gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    FutureSlot {
        signature_slot: Slot,
        latest_permissible_slot: Slot,
    },
    /// The attestation is from a slot that is prior to the earliest permissible slot (with
    /// respect to the gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    PastSlot {
        signature_slot: Slot,
        earliest_permissible_slot: Slot,
    },
    /// The attestations aggregation bits were empty when they shouldn't be.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    EmptyAggregationBitfield,
    /// The `selection_proof` on the aggregate atte) = get_valid_sync_signature(harnstation does not elect it as an aggregator.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidSelectionProof {
        aggregator_index: u64,
    },
    /// The `selection_proof` on the aggregate attestation selects it as a validator, however the
    /// aggregator index is not in the committee for that attestation.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    AggregatorNotInCommittee {
        aggregator_index: u64,
    },
    /// The aggregator index refers to a validator index that we have not seen.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    AggregatorPubkeyUnknown(u64),
    /// The attestation has been seen before; either in a block, on the gossip network or from a
    /// local validator.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this attestation is valid, however we have already observed it and do not
    /// need to observe it again.
    AttestationAlreadyKnown(Hash256),
    /// There has already been an aggregation observed for this validator, we refuse to process a
    /// second.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this attestation is valid, however we have already observed an aggregate
    /// attestation from this validator for this epoch and should not observe another.
    AggregatorAlreadyKnown(u64),
    /// The aggregator index is higher than the maximum possible validator count.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    ValidatorIndexTooHigh(usize),
    /// The aggregator index is higher than the maximum possible validator count.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    UnknowValidatorIndex(usize),
    /// The `attestation.data.beacon_block_root` block is unknown.
    ///
    /// ## Peer scoring
    ///
    /// The attestation points to a block we have not yet imported. It's unclear if the attestation
    /// is valid or not.
    UnknownHeadBlock {
        beacon_block_root: Hash256,
    },
    /// A signature on the attestation is invalid.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidSignature,
    /// We have already observed a signature for the `validator_index` and refuse to process
    /// another.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this sync signature is valid, however we have already observed a
    /// signature from this validator for this slot and should not observe
    /// another.
    PriorSyncSignatureKnown {
        validator_index: u64,
        slot: Slot,
    },
    /// The attestation was received on an invalid attestation subnet.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidSubnetId {
        received: SyncSubnetId,
        expected: Vec<SyncSubnetId>,
    },
    /// The sync signature failed the `state_processing` verification stage.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    Invalid(SyncSignatureValidationError),
    /// The attestation head block is too far behind the attestation slot, causing many skip slots.
    /// This is deemed a DoS risk.
    TooManySkippedSlots {
        head_block_slot: Slot,
        attestation_slot: Slot,
    },
    /// There was an error whilst processing the attestation. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this attestation due to an internal error. It's unclear if the
    /// attestation is valid.
    BeaconChainError(BeaconChainError),
    /// There was an error whilst processing the attestation. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this attestation due to an internal error. It's unclear if the
    /// attestation is valid.
    InvalidSubcommittee {
        subcommittee_index: u64,
        subcommittee_size: u64,
    },
    SyncCommitteeCacheNotInitialized,
    ArithError(ArithError),
    SszError(ssz_types::Error),
    ContributionError(ContributionError),
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChainError(e)
    }
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Error::ArithError(e)
    }
}

impl From<ContributionError> for Error {
    fn from(e: ContributionError) -> Self {
        Error::ContributionError(e)
    }
}

/// Wraps a `SignedContributionAndProof` that has been verified for propagation on the gossip network.
pub struct VerifiedSyncContribution<T: BeaconChainTypes> {
    signed_aggregate: SignedContributionAndProof<T::EthSpec>,
}

/// Custom `Clone` implementation is to avoid the restrictive trait bounds applied by the usual derive
/// macro.
impl<T: BeaconChainTypes> Clone for VerifiedSyncContribution<T> {
    fn clone(&self) -> Self {
        Self {
            signed_aggregate: self.signed_aggregate.clone(),
        }
    }
}

/// Wraps a `SyncCommitteeSignature` that has been verified for propagation on the gossip network.
pub struct VerifiedSyncSignature {
    sync_signature: SyncCommitteeSignature,
    subnet_positions: HashMap<SyncSubnetId, Vec<usize>>,
}

/// Custom `Clone` implementation is to avoid the restrictive trait bounds applied by the usual derive
/// macro.
impl Clone for VerifiedSyncSignature {
    fn clone(&self) -> Self {
        Self {
            sync_signature: self.sync_signature.clone(),
            subnet_positions: self.subnet_positions.clone(),
        }
    }
}

impl<T: BeaconChainTypes> VerifiedSyncContribution<T> {
    /// Returns `Ok(Self)` if the `signed_aggregate` is valid to be (re)published on the gossip
    /// network.
    pub fn verify(
        signed_aggregate: SignedContributionAndProof<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        let aggregator_index = signed_aggregate.message.aggregator_index;
        let contribution = &signed_aggregate.message.contribution;

        // Ensure sync committee signature is within the MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance.
        verify_propagation_slot_range(chain, contribution)?;

        // Validate subcommittee index.
        if contribution.subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT {
            return Err(Error::InvalidSubcommittee {
                subcommittee_index: contribution.subcommittee_index,
                subcommittee_size: SYNC_COMMITTEE_SUBNET_COUNT,
            });
        }

        // Ensure the valid aggregated attestation has not already been seen locally.
        let contribution_root = contribution.tree_hash_root();
        if chain
            .observed_sync_contributions
            .write()
            .is_known(contribution, contribution_root)
            .map_err(|e| Error::BeaconChainError(e.into()))?
        {
            return Err(Error::AttestationAlreadyKnown(contribution_root));
        }

        // Ensure there has been no other observed aggregate for the given `aggregator_index`.
        //
        // Note: do not observe yet, only observe once the attestation has been verified.
        match chain
            .observed_sync_aggregators
            .read()
            .validator_has_been_observed(contribution.slot, aggregator_index as usize)
        {
            Ok(true) => Err(Error::AggregatorAlreadyKnown(aggregator_index)),
            Ok(false) => Ok(()),
            Err(ObservedAttestersError::ValidatorIndexTooHigh(i)) => {
                Err(Error::ValidatorIndexTooHigh(i))
            }
            Err(e) => Err(BeaconChainError::from(e).into()),
        }?;

        // Ensure the block being voted for (attestation.data.beacon_block_root) passes validation.
        // Don't enforce the skip slot restriction for aggregates.
        //
        // This indirectly checks to see if the `attestation.data.beacon_block_root` is in our fork
        // choice. Any known, non-finalized, processed block should be in fork choice, so this
        // check immediately filters out attestations that attest to a block that has not been
        // processed.
        //
        // Attestations must be for a known block. If the block is unknown, we simply drop the
        // attestation and do not delay consideration for later.
        let _head_block =
            verify_head_block_is_known(chain, contribution, contribution.beacon_block_root, None)?;

        // Ensure that the attestation has participants.
        if contribution.aggregation_bits.is_zero() {
            return Err(Error::EmptyAggregationBitfield);
        }

        // Note: this clones the signature which is known to be a relatively slow operation.
        //
        // Future optimizations should remove this clone.
        let selection_proof =
            SyncSelectionProof::from(signed_aggregate.message.selection_proof.clone());

        if !selection_proof
            .is_aggregator::<T::EthSpec>()
            .map_err(|e| Error::BeaconChainError(e.into()))?
        {
            return Err(Error::InvalidSelectionProof { aggregator_index });
        }

        // Ensure the aggregator's pubkey is in the declared subcommittee of the current sync committee
        let pubkey_bytes = chain
            .validator_pubkey_bytes(aggregator_index as usize)?
            .ok_or(Error::UnknowValidatorIndex(aggregator_index as usize))?;
        let current_sync_committee = chain.head_current_sync_committee()?;

        let subcommittee_index = contribution.subcommittee_index as usize;

        let sync_subcommittee_size =
            T::EthSpec::sync_committee_size().safe_div(SYNC_COMMITTEE_SUBNET_COUNT as usize)?;
        let start_subcommittee = subcommittee_index.safe_mul(sync_subcommittee_size)?;
        let end_subcommittee = start_subcommittee.safe_add(sync_subcommittee_size)?;

        if !current_sync_committee.pubkeys[start_subcommittee..end_subcommittee]
            .contains(&pubkey_bytes)
        {
            return Err(Error::AggregatorNotInCommittee { aggregator_index });
        };

        // only iter through the correct partition
        let participant_indices = current_sync_committee.pubkeys
            [start_subcommittee..end_subcommittee]
            .iter()
            .zip(contribution.aggregation_bits.iter())
            .flat_map(|(pubkey, bit)| {
                bit.then::<Result<usize, Error>, _>(|| {
                    chain
                        .validator_index(&pubkey)?
                        .ok_or(Error::UnknowValidatorIndex(aggregator_index as usize))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Ensure that all signatures are valid.
        if let Err(e) = verify_signed_aggregate_signatures(
            chain,
            &signed_aggregate,
            participant_indices.as_slice(),
        )
        .and_then(|is_valid| {
            if !is_valid {
                Err(Error::InvalidSignature)
            } else {
                Ok(())
            }
        }) {
            return Err(e);
        }
        let contribution = &signed_aggregate.message.contribution;
        let aggregator_index = signed_aggregate.message.aggregator_index;

        // Observe the valid sync contribution so we do not re-process it.
        //
        // It's important to double check that the contribution is not already known, otherwise two
        // contribution processed at the same time could be published.
        if let ObserveOutcome::AlreadyKnown = chain
            .observed_sync_contributions
            .write()
            .observe_item(contribution, Some(contribution_root))
            .map_err(|e| Error::BeaconChainError(e.into()))?
        {
            return Err(Error::AttestationAlreadyKnown(contribution_root));
        }

        // Observe the aggregator so we don't process another aggregate from them.
        //
        // It's important to double check that the attestation is not already known, otherwise two
        // attestations processed at the same time could be published.
        if chain
            .observed_sync_aggregators
            .write()
            .observe_validator(contribution.slot, aggregator_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorSyncSignatureKnown {
                validator_index: aggregator_index,
                slot: contribution.slot,
            });
        }
        Ok(VerifiedSyncContribution { signed_aggregate })
    }

    /// A helper function to add this aggregate to `beacon_chain.op_pool`.
    pub fn add_to_pool(self, chain: &BeaconChain<T>) -> Result<Self, Error> {
        chain.add_contribution_to_block_inclusion_pool(self)
    }

    /// Returns the underlying `contribution` for the `signed_aggregate`.
    pub fn contribution(&self) -> &SyncCommitteeContribution<T::EthSpec> {
        &self.signed_aggregate.message.contribution
    }

    /// Returns the underlying `signed_aggregate`.
    pub fn aggregate(&self) -> &SignedContributionAndProof<T::EthSpec> {
        &self.signed_aggregate
    }
}

impl VerifiedSyncSignature {
    /// Returns `Ok(Self)` if the `sync_signature` is valid to be (re)published on the gossip
    /// network.
    ///
    /// `subnet_id` is the subnet from which we received this attestation. This function will
    /// verify that it was received on the correct subnet.
    pub fn verify<T: BeaconChainTypes>(
        sync_signature: SyncCommitteeSignature,
        subnet_id: Option<SyncSubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        // Ensure sync committee signature is for the current slot (within a
        // MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance).
        //
        // We do not queue future attestations for later processing.
        verify_propagation_slot_range(chain, &sync_signature)?;

        // Attestations must be for a known block. If the block is unknown, we simply drop the
        // attestation and do not delay consideration for later.
        //
        // Enforce a maximum skip distance for unaggregated attestations.
        verify_head_block_is_known(
            chain,
            &sync_signature,
            sync_signature.beacon_block_root,
            chain.config.import_max_skip_slots,
        )?;
        let sync_subcommittee_size =
            <<T as BeaconChainTypes>::EthSpec as EthSpec>::SyncCommitteeSize::to_usize()
                .safe_div(SYNC_COMMITTEE_SUBNET_COUNT as usize)?;
        let pubkey = chain
            .validator_pubkey_bytes(sync_signature.validator_index as usize)?
            .ok_or(Error::UnknowValidatorIndex(
                sync_signature.validator_index as usize,
            ))?;

        let current_sync_committee = chain.head_current_sync_committee()?;
        let mut subnet_positions = HashMap::new();
        for (committee_index, validator_pubkey) in current_sync_committee.pubkeys.iter().enumerate()
        {
            if pubkey == *validator_pubkey {
                let subcommittee_index = committee_index.safe_div(sync_subcommittee_size)?;
                let position_in_subcommittee = committee_index.safe_rem(sync_subcommittee_size)?;
                subnet_positions
                    .entry(SyncSubnetId::new(subcommittee_index as u64))
                    .or_insert_with(Vec::new)
                    .push(position_in_subcommittee);
            }
        }

        if let Some(subnet_id) = subnet_id {
            if !subnet_positions.contains_key(&subnet_id) {
                return Err(Error::InvalidSubnetId {
                    received: subnet_id,
                    expected: subnet_positions.keys().cloned().collect::<Vec<_>>(),
                });
            }
        };

        /*
         * The attestation is the first valid attestation received for the participating validator
         * for the slot, attestation.data.slot.
         */
        let validator_index = sync_signature.validator_index;
        if chain
            .observed_sync_contributors
            .read()
            .validator_has_been_observed(sync_signature.slot, validator_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorSyncSignatureKnown {
                validator_index,
                slot: sync_signature.slot,
            });
        }

        // The aggregate signature of the attestation is valid.
        verify_sync_signature(chain, &sync_signature)?;

        // Now that the attestation has been fully verified, store that we have received a valid
        // attestation from this validator.
        //
        // It's important to double check that the attestation still hasn't been observed, since
        // there can be a race-condition if we receive two attestations at the same time and
        // process them in different threads.
        if chain
            .observed_sync_contributors
            .write()
            .observe_validator(sync_signature.slot, validator_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorSyncSignatureKnown {
                validator_index,
                slot: sync_signature.slot,
            });
        }

        Ok(Self {
            sync_signature,
            subnet_positions,
        })
    }

    /// A helper function to add this attestation to `beacon_chain.naive_aggregation_pool`.
    pub fn add_to_pool<T: BeaconChainTypes>(self, chain: &BeaconChain<T>) -> Result<Self, Error> {
        chain.add_to_naive_sync_aggregation_pool(self)
    }

    /// Returns the correct subnet for the attestation.
    pub fn subnet_positions(&self) -> HashMap<SyncSubnetId, Vec<usize>> {
        self.subnet_positions.clone()
    }

    /// Returns the wrapped `attestation`.
    pub fn sync_signature(&self) -> &SyncCommitteeSignature {
        &self.sync_signature
    }
}

/// Returns `Ok(())` if the `attestation.data.beacon_block_root` is known to this chain.
/// You can use this `shuffling_id` to read from the shuffling cache.
///
/// The block root may not be known for two reasons:
///
/// 1. The block has never been verified by our application.
/// 2. The block is prior to the latest finalized block.
///
/// Case (1) is the exact thing we're trying to detect. However case (2) is a little different, but
/// it's still fine to reject here because there's no need for us to handle attestations that are
/// already finalized.
fn verify_head_block_is_known<T: BeaconChainTypes, E: SlotData>(
    chain: &BeaconChain<T>,
    sync_contribution: &E,
    beacon_block_root: Hash256,
    max_skip_slots: Option<u64>,
) -> Result<ProtoBlock, Error> {
    if let Some(block) = chain.fork_choice.read().get_block(&beacon_block_root) {
        //TODO: do we want to keep this?
        // Reject any block that exceeds our limit on skipped slots.
        if let Some(max_skip_slots) = max_skip_slots {
            if sync_contribution.get_slot() > block.slot + max_skip_slots {
                return Err(Error::TooManySkippedSlots {
                    head_block_slot: block.slot,
                    attestation_slot: sync_contribution.get_slot(),
                });
            }
        }

        Ok(block)
    } else {
        Err(Error::UnknownHeadBlock { beacon_block_root })
    }
}

/// Verify that the `attestation` is within the acceptable gossip propagation range, with reference
/// to the current slot of the `chain`.
///
/// Accounts for `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
pub fn verify_propagation_slot_range<T: BeaconChainTypes, E: SlotData>(
    chain: &BeaconChain<T>,
    sync_contribution: &E,
) -> Result<(), Error> {
    let signature_slot = sync_contribution.get_slot();

    let latest_permissible_slot = chain
        .slot_clock
        .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if signature_slot > latest_permissible_slot {
        return Err(Error::FutureSlot {
            signature_slot,
            latest_permissible_slot,
        });
    }

    // Taking advantage of saturating subtraction on `Slot`.
    let earliest_permissible_slot = chain
        .slot_clock
        .now_with_past_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or(BeaconChainError::UnableToReadSlot)?;

    if signature_slot < earliest_permissible_slot {
        return Err(Error::PastSlot {
            signature_slot,
            earliest_permissible_slot,
        });
    }

    Ok(())
}

/// Verifies all the signatures in a `SignedContributionAndProof` using BLS batch verification. This
/// includes three signatures:
///
/// - `signed_aggregate.signature`
/// - `signed_aggregate.message.selection_proof`
/// - `signed_aggregate.message.aggregate.signature`
///
/// # Returns
///
/// - `Ok(true)`: if all signatures are valid.
/// - `Ok(false)`: if one or more signatures are invalid.
/// - `Err(e)`: if there was an error preventing signature verification.
pub fn verify_signed_aggregate_signatures<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    signed_aggregate: &SignedContributionAndProof<T::EthSpec>,
    participant_indices: &[usize],
) -> Result<bool, Error> {
    let pubkey_cache = chain
        .validator_pubkey_cache
        .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
        .ok_or(BeaconChainError::ValidatorPubkeyCacheLockTimeout)?;

    let aggregator_index = signed_aggregate.message.aggregator_index;
    if aggregator_index >= pubkey_cache.len() as u64 {
        return Err(Error::AggregatorPubkeyUnknown(aggregator_index));
    }

    let fork = chain
        .canonical_head
        .try_read_for(HEAD_LOCK_TIMEOUT)
        .ok_or(BeaconChainError::CanonicalHeadLockTimeout)
        .map(|head| head.beacon_state.fork())?;

    let signature_sets = vec![
        signed_sync_aggregate_selection_proof_signature_set(
            |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
            &signed_aggregate,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
        .map_err(BeaconChainError::SignatureSetError)?,
        signed_sync_aggregate_signature_set(
            |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
            &signed_aggregate,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
        .map_err(BeaconChainError::SignatureSetError)?,
        sync_committee_contribution_signature_set_from_pubkeys::<T::EthSpec, _>(
            |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
            participant_indices,
            &signed_aggregate.message.contribution.signature,
            signed_aggregate
                .message
                .contribution
                .slot
                .epoch(T::EthSpec::slots_per_epoch()),
            signed_aggregate.message.contribution.beacon_block_root,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
        .map_err(BeaconChainError::SignatureSetError)?,
    ];

    Ok(verify_signature_sets(signature_sets.iter()))
}

/// Verifies that the signature of the `sync_signature` is valid.
pub fn verify_sync_signature<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    sync_signature: &SyncCommitteeSignature,
) -> Result<(), Error> {
    let signature_setup_timer =
        metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_SETUP_TIMES);

    let pubkey_cache = chain
        .validator_pubkey_cache
        .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
        .ok_or(BeaconChainError::ValidatorPubkeyCacheLockTimeout)?;

    let fork = chain
        .canonical_head
        .try_read_for(HEAD_LOCK_TIMEOUT)
        .ok_or(BeaconChainError::CanonicalHeadLockTimeout)
        .map(|head| head.beacon_state.fork())?;

    let agg_sig = AggregateSignature::from(&sync_signature.signature);
    let signature_set = sync_committee_contribution_signature_set_from_pubkeys::<T::EthSpec, _>(
        |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
        &[sync_signature.validator_index as usize],
        &agg_sig,
        sync_signature.slot.epoch(T::EthSpec::slots_per_epoch()),
        sync_signature.beacon_block_root,
        &fork,
        chain.genesis_validators_root,
        &chain.spec,
    )
    .map_err(BeaconChainError::SignatureSetError)?;

    metrics::stop_timer(signature_setup_timer);

    let _signature_verification_timer =
        metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_TIMES);

    if signature_set.verify() {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}
