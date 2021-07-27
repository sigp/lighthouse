//! Provides verification for the following sync committee messages:
//!
//! - "Unaggregated" `SyncCommitteeMessage` received from either gossip or the HTTP API.
//! - "Aggregated" `SignedContributionAndProof` received from gossip or the HTTP API.
//!
//! For clarity, we define:
//!
//! - Unaggregated: a `SyncCommitteeMessage` object.
//! - Aggregated: a `SignedContributionAndProof` which has zero or more signatures.
//!   - Note: "zero or more" may soon change to "one or more".
//!
//! Similar to the `crate::block_verification` module, we try to avoid doing duplicate verification
//! work as a sync committee message passes through different stages of verification. We represent these
//! different stages of verification with wrapper types. These wrapper-types flow in a particular
//! pattern:
//!
//! ```ignore
//!      types::SyncCommitteeMessage      types::SignedContributionAndProof
//!              |                                    |
//!              ▼                                    ▼
//!      VerifiedSyncCommitteeMessage               VerifiedSyncContribution
//!              |                                    |
//!              -------------------------------------
//!                                |
//!                                ▼
//!                  impl SignatureVerifiedSyncContribution
//! ```

use crate::observed_attesters::SlotSubcommitteeIndex;
use crate::{
    beacon_chain::{MAXIMUM_GOSSIP_CLOCK_DISPARITY, VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT},
    metrics,
    observed_aggregates::ObserveOutcome,
    BeaconChain, BeaconChainError, BeaconChainTypes,
};
use bls::{verify_signature_sets, PublicKeyBytes};
use derivative::Derivative;
use safe_arith::ArithError;
use slot_clock::SlotClock;
use state_processing::per_block_processing::errors::SyncCommitteeMessageValidationError;
use state_processing::signature_sets::{
    signed_sync_aggregate_selection_proof_signature_set, signed_sync_aggregate_signature_set,
    sync_committee_contribution_signature_set_from_pubkeys,
    sync_committee_message_set_from_pubkeys,
};
use std::borrow::Cow;
use std::collections::HashMap;
use strum::AsRefStr;
use tree_hash::TreeHash;
use types::consts::altair::SYNC_COMMITTEE_SUBNET_COUNT;
use types::slot_data::SlotData;
use types::sync_committee::Error as SyncCommitteeError;
use types::{
    sync_committee_contribution::Error as ContributionError, AggregateSignature, BeaconStateError,
    EthSpec, Hash256, SignedContributionAndProof, Slot, SyncCommitteeContribution,
    SyncCommitteeMessage, SyncSelectionProof, SyncSubnetId,
};

/// Returned when a sync committee contribution was not successfully verified. It might not have been verified for
/// two reasons:
///
/// - The sync committee message is malformed or inappropriate for the context (indicated by all variants
///   other than `BeaconChainError`).
/// - The application encountered an internal error whilst attempting to determine validity
///   (the `BeaconChainError` variant)
#[derive(Debug, AsRefStr)]
pub enum Error {
    /// The sync committee message is from a slot that is later than the current slot (with respect to the
    /// gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    FutureSlot {
        message_slot: Slot,
        latest_permissible_slot: Slot,
    },
    /// The sync committee message is from a slot that is prior to the earliest permissible slot (with
    /// respect to the gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    PastSlot {
        message_slot: Slot,
        earliest_permissible_slot: Slot,
    },
    /// The sync committee message's aggregation bits were empty when they shouldn't be.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    EmptyAggregationBitfield,
    /// The `selection_proof` on the sync contribution does not elect it as an aggregator.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidSelectionProof { aggregator_index: u64 },
    /// The `selection_proof` on the sync committee contribution selects it as a validator, however the
    /// aggregator index is not in the committee for that sync contribution.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    AggregatorNotInCommittee { aggregator_index: u64 },
    /// The aggregator index refers to a validator index that we have not seen.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    AggregatorPubkeyUnknown(u64),
    /// The sync contribution has been seen before; either in a block, on the gossip network or from a
    /// local validator.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this sync contribution is valid, however we have already observed it and do not
    /// need to observe it again.
    SyncContributionAlreadyKnown(Hash256),
    /// There has already been an aggregation observed for this validator, we refuse to process a
    /// second.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this sync committee message is valid, however we have already observed an aggregate
    /// sync committee message from this validator for this epoch and should not observe another.
    AggregatorAlreadyKnown(u64),
    /// The aggregator index is higher than the maximum possible validator count.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    UnknownValidatorIndex(usize),
    /// The public key of the validator has not been seen locally.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this sync committee message is valid, however we have already observed an aggregate
    /// sync committee message from this validator for this epoch and should not observe another.
    UnknownValidatorPubkey(PublicKeyBytes),
    /// A signature on the sync committee message is invalid.
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
    /// It's unclear if this sync message is valid, however we have already observed a
    /// signature from this validator for this slot and should not observe
    /// another.
    PriorSyncCommitteeMessageKnown { validator_index: u64, slot: Slot },
    /// The sync committee message was received on an invalid sync committee message subnet.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidSubnetId {
        received: SyncSubnetId,
        expected: Vec<SyncSubnetId>,
    },
    /// The sync message failed the `state_processing` verification stage.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    Invalid(SyncCommitteeMessageValidationError),
    /// There was an error whilst processing the sync contribution. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this sync committee message due to an internal error. It's unclear if the
    /// sync committee message is valid.
    BeaconChainError(BeaconChainError),
    /// There was an error whilst processing the sync contribution. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this sync committee message due to an internal error. It's unclear if the
    /// sync committee message is valid.
    BeaconStateError(BeaconStateError),
    /// There was an error whilst processing the sync contribution. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this sync committee message due to an internal error. It's unclear if the
    /// sync committee message is valid.
    InvalidSubcommittee {
        subcommittee_index: u64,
        subcommittee_size: u64,
    },
    /// There was an error whilst processing the sync contribution. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this sync committee message due to an internal error. It's unclear if the
    /// sync committee message is valid.
    ArithError(ArithError),
    /// There was an error whilst processing the sync contribution. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this sync committee message due to an internal error. It's unclear if the
    /// sync committee message is valid.
    ContributionError(ContributionError),
    /// There was an error whilst processing the sync contribution. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this sync committee message due to an internal error. It's unclear if the
    /// sync committee message is valid.
    SyncCommitteeError(SyncCommitteeError),
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChainError(e)
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconStateError(e)
    }
}

impl From<SyncCommitteeError> for Error {
    fn from(e: SyncCommitteeError) -> Self {
        Error::SyncCommitteeError(e)
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

/// Wraps a `SignedContributionAndProof` that has been verified for propagation on the gossip network.\
#[derive(Derivative)]
#[derivative(Clone(bound = "T: BeaconChainTypes"))]
pub struct VerifiedSyncContribution<T: BeaconChainTypes> {
    signed_aggregate: SignedContributionAndProof<T::EthSpec>,
    participant_pubkeys: Vec<PublicKeyBytes>,
}

/// Wraps a `SyncCommitteeMessage` that has been verified for propagation on the gossip network.
#[derive(Clone)]
pub struct VerifiedSyncCommitteeMessage {
    sync_message: SyncCommitteeMessage,
    subnet_positions: HashMap<SyncSubnetId, Vec<usize>>,
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
        let subcommittee_index = contribution.subcommittee_index as usize;

        // Ensure sync committee contribution is within the MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance.
        verify_propagation_slot_range(chain, contribution)?;

        // Validate subcommittee index.
        if contribution.subcommittee_index >= SYNC_COMMITTEE_SUBNET_COUNT {
            return Err(Error::InvalidSubcommittee {
                subcommittee_index: contribution.subcommittee_index,
                subcommittee_size: SYNC_COMMITTEE_SUBNET_COUNT,
            });
        }

        // Ensure that the sync committee message has participants.
        if contribution.aggregation_bits.is_zero() {
            return Err(Error::EmptyAggregationBitfield);
        }

        // Ensure the aggregator's pubkey is in the declared subcommittee of the current sync committee
        let pubkey_bytes = chain
            .validator_pubkey_bytes(aggregator_index as usize)?
            .ok_or(Error::UnknownValidatorIndex(aggregator_index as usize))?;
        let sync_subcommittee_pubkeys = chain
            .sync_committee_at_next_slot(contribution.get_slot())?
            .get_subcommittee_pubkeys(subcommittee_index)?;

        if !sync_subcommittee_pubkeys.contains(&pubkey_bytes) {
            return Err(Error::AggregatorNotInCommittee { aggregator_index });
        };

        // Ensure the valid sync contribution has not already been seen locally.
        let contribution_root = contribution.tree_hash_root();
        if chain
            .observed_sync_contributions
            .write()
            .is_known(contribution, contribution_root)
            .map_err(|e| Error::BeaconChainError(e.into()))?
        {
            return Err(Error::SyncContributionAlreadyKnown(contribution_root));
        }

        // Ensure there has been no other observed aggregate for the given `aggregator_index`.
        //
        // Note: do not observe yet, only observe once the sync contribution has been verified.
        let observed_key =
            SlotSubcommitteeIndex::new(contribution.slot, contribution.subcommittee_index);
        match chain
            .observed_sync_aggregators
            .read()
            .validator_has_been_observed(observed_key, aggregator_index as usize)
        {
            Ok(true) => Err(Error::AggregatorAlreadyKnown(aggregator_index)),
            Ok(false) => Ok(()),
            Err(e) => Err(BeaconChainError::from(e).into()),
        }?;

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

        // Gather all validator pubkeys that signed this contribution.
        let participant_pubkeys = sync_subcommittee_pubkeys
            .into_iter()
            .zip(contribution.aggregation_bits.iter())
            .filter_map(|(pubkey, bit)| bit.then(|| pubkey))
            .collect::<Vec<_>>();

        // Ensure that all signatures are valid.
        if !verify_signed_aggregate_signatures(
            chain,
            &signed_aggregate,
            participant_pubkeys.as_slice(),
        )? {
            return Err(Error::InvalidSignature);
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
            return Err(Error::SyncContributionAlreadyKnown(contribution_root));
        }

        // Observe the aggregator so we don't process another aggregate from them.
        //
        // It's important to double check that the sync committee message is not already known, otherwise two
        // sync committee messages processed at the same time could be published.
        if chain
            .observed_sync_aggregators
            .write()
            .observe_validator(observed_key, aggregator_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorSyncCommitteeMessageKnown {
                validator_index: aggregator_index,
                slot: contribution.slot,
            });
        }
        Ok(VerifiedSyncContribution {
            signed_aggregate,
            participant_pubkeys,
        })
    }

    /// A helper function to add this aggregate to `beacon_chain.op_pool`.
    pub fn add_to_pool(self, chain: &BeaconChain<T>) -> Result<(), Error> {
        chain.add_contribution_to_block_inclusion_pool(self)
    }

    /// Returns the underlying `contribution` for the `signed_aggregate`.
    pub fn contribution(self) -> SyncCommitteeContribution<T::EthSpec> {
        self.signed_aggregate.message.contribution
    }

    /// Returns the underlying `signed_aggregate`.
    pub fn aggregate(&self) -> &SignedContributionAndProof<T::EthSpec> {
        &self.signed_aggregate
    }

    /// Returns the pubkeys of all validators that are included in the aggregate.
    pub fn participant_pubkeys(&self) -> &[PublicKeyBytes] {
        &self.participant_pubkeys
    }
}

impl VerifiedSyncCommitteeMessage {
    /// Returns `Ok(Self)` if the `sync_message` is valid to be (re)published on the gossip
    /// network.
    ///
    /// `subnet_id` is the subnet from which we received this sync message. This function will
    /// verify that it was received on the correct subnet.
    pub fn verify<T: BeaconChainTypes>(
        sync_message: SyncCommitteeMessage,
        subnet_id: SyncSubnetId,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        // Ensure sync committee message is for the current slot (within a
        // MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance).
        //
        // We do not queue future sync committee messages for later processing.
        verify_propagation_slot_range(chain, &sync_message)?;

        // Ensure the `subnet_id` is valid for the given validator.
        let pubkey = chain
            .validator_pubkey_bytes(sync_message.validator_index as usize)?
            .ok_or(Error::UnknownValidatorIndex(
                sync_message.validator_index as usize,
            ))?;

        let sync_committee = chain.sync_committee_at_next_slot(sync_message.get_slot())?;
        let subnet_positions = sync_committee.subcommittee_positions_for_public_key(&pubkey)?;

        if !subnet_positions.contains_key(&subnet_id) {
            return Err(Error::InvalidSubnetId {
                received: subnet_id,
                expected: subnet_positions.keys().cloned().collect::<Vec<_>>(),
            });
        }

        // The sync committee message is the first valid message received for the participating validator
        // for the slot, sync_message.slot.
        let validator_index = sync_message.validator_index;
        if chain
            .observed_sync_contributors
            .read()
            .validator_has_been_observed(
                SlotSubcommitteeIndex::new(sync_message.slot, subnet_id.into()),
                validator_index as usize,
            )
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorSyncCommitteeMessageKnown {
                validator_index,
                slot: sync_message.slot,
            });
        }

        // The aggregate signature of the sync committee message is valid.
        verify_sync_committee_message(chain, &sync_message, &pubkey)?;

        // Now that the sync committee message has been fully verified, store that we have received a valid
        // sync committee message from this validator.
        //
        // It's important to double check that the sync committee message still hasn't been observed, since
        // there can be a race-condition if we receive two sync committee messages at the same time and
        // process them in different threads.
        if chain
            .observed_sync_contributors
            .write()
            .observe_validator(
                SlotSubcommitteeIndex::new(sync_message.slot, subnet_id.into()),
                validator_index as usize,
            )
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorSyncCommitteeMessageKnown {
                validator_index,
                slot: sync_message.slot,
            });
        }

        Ok(Self {
            sync_message,
            subnet_positions,
        })
    }

    /// A helper function to add this sync committee message to `beacon_chain.naive_sync_aggregation_pool`.
    pub fn add_to_pool<T: BeaconChainTypes>(self, chain: &BeaconChain<T>) -> Result<Self, Error> {
        chain.add_to_naive_sync_aggregation_pool(self)
    }

    /// Returns the subcommittee positions for the sync message, keyed on the `SyncSubnetId` for
    /// the subnets the signature should be sent on.
    pub fn subnet_positions(&self) -> &HashMap<SyncSubnetId, Vec<usize>> {
        &self.subnet_positions
    }

    /// Returns the wrapped `SyncCommitteeMessage`.
    pub fn sync_message(&self) -> &SyncCommitteeMessage {
        &self.sync_message
    }
}

/// Verify that the `sync_contribution` is within the acceptable gossip propagation range, with reference
/// to the current slot of the `chain`.
///
/// Accounts for `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
pub fn verify_propagation_slot_range<T: BeaconChainTypes, U: SlotData>(
    chain: &BeaconChain<T>,
    sync_contribution: &U,
) -> Result<(), Error> {
    let message_slot = sync_contribution.get_slot();

    let latest_permissible_slot = chain
        .slot_clock
        .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if message_slot > latest_permissible_slot {
        return Err(Error::FutureSlot {
            message_slot,
            latest_permissible_slot,
        });
    }

    let earliest_permissible_slot = chain
        .slot_clock
        .now_with_past_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or(BeaconChainError::UnableToReadSlot)?;

    if message_slot < earliest_permissible_slot {
        return Err(Error::PastSlot {
            message_slot,
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
    participant_pubkeys: &[PublicKeyBytes],
) -> Result<bool, Error> {
    let pubkey_cache = chain
        .validator_pubkey_cache
        .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
        .ok_or(BeaconChainError::ValidatorPubkeyCacheLockTimeout)?;

    let aggregator_index = signed_aggregate.message.aggregator_index;
    if aggregator_index >= pubkey_cache.len() as u64 {
        return Err(Error::AggregatorPubkeyUnknown(aggregator_index));
    }

    let next_slot_epoch =
        (signed_aggregate.message.contribution.slot + 1).epoch(T::EthSpec::slots_per_epoch());
    let fork = chain.spec.fork_at_epoch(next_slot_epoch);

    let signature_sets = vec![
        signed_sync_aggregate_selection_proof_signature_set(
            |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
            signed_aggregate,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
        .map_err(BeaconChainError::SignatureSetError)?,
        signed_sync_aggregate_signature_set(
            |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
            signed_aggregate,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
        .map_err(BeaconChainError::SignatureSetError)?,
        sync_committee_contribution_signature_set_from_pubkeys::<T::EthSpec, _>(
            |validator_index| {
                pubkey_cache
                    .get_pubkey_from_pubkey_bytes(validator_index)
                    .map(Cow::Borrowed)
            },
            participant_pubkeys,
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

/// Verifies that the signature of the `sync_message` is valid.
pub fn verify_sync_committee_message<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    sync_message: &SyncCommitteeMessage,
    pubkey_bytes: &PublicKeyBytes,
) -> Result<(), Error> {
    let signature_setup_timer =
        metrics::start_timer(&metrics::SYNC_MESSAGE_PROCESSING_SIGNATURE_SETUP_TIMES);

    let pubkey_cache = chain
        .validator_pubkey_cache
        .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
        .ok_or(BeaconChainError::ValidatorPubkeyCacheLockTimeout)?;

    let pubkey = pubkey_cache
        .get_pubkey_from_pubkey_bytes(pubkey_bytes)
        .map(Cow::Borrowed)
        .ok_or_else(|| Error::UnknownValidatorPubkey(*pubkey_bytes))?;

    let next_slot_epoch = (sync_message.get_slot() + 1).epoch(T::EthSpec::slots_per_epoch());
    let fork = chain.spec.fork_at_epoch(next_slot_epoch);

    let agg_sig = AggregateSignature::from(&sync_message.signature);
    let signature_set = sync_committee_message_set_from_pubkeys::<T::EthSpec>(
        pubkey,
        &agg_sig,
        sync_message.slot.epoch(T::EthSpec::slots_per_epoch()),
        sync_message.beacon_block_root,
        &fork,
        chain.genesis_validators_root,
        &chain.spec,
    )
    .map_err(BeaconChainError::SignatureSetError)?;

    metrics::stop_timer(signature_setup_timer);

    let _signature_verification_timer =
        metrics::start_timer(&metrics::SYNC_MESSAGE_PROCESSING_SIGNATURE_TIMES);

    if signature_set.verify() {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}
