//! Provides verification for the following attestations:
//!
//! - "Unaggregated" `Attestation` received from either gossip or the HTTP API.
//! - "Aggregated" `SignedAggregateAndProof` received from gossip or the HTTP API.
//!
//! For clarity, we define:
//!
//! - Unaggregated: an `Attestation` object that has exactly one aggregation bit set.
//! - Aggregated: a `SignedAggregateAndProof` which has zero or more signatures.
//!   - Note: "zero or more" may soon change to "one or more".
//!
//! Similar to the `crate::block_verification` module, we try to avoid doing duplicate verification
//! work as an attestation passes through different stages of verification. We represent these
//! different stages of verification with wrapper types. These wrapper-types flow in a particular
//! pattern:
//!
//! ```ignore
//!      types::Attestation              types::SignedAggregateAndProof
//!              |                                    |
//!              ▼                                    ▼
//!  IndexedUnaggregatedAttestation     IndexedAggregatedAttestation
//!              |                                    |
//!  VerifiedUnaggregatedAttestation    VerifiedAggregatedAttestation
//!              |                                    |
//!              -------------------------------------
//!                                |
//!                                ▼
//!                  impl VerifiedAttestation
//! ```
mod batch;

use crate::{
    beacon_chain::{MAXIMUM_GOSSIP_CLOCK_DISPARITY, VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT},
    metrics,
    observed_aggregates::ObserveOutcome,
    observed_attesters::Error as ObservedAttestersError,
    BeaconChain, BeaconChainError, BeaconChainTypes,
};
use bls::verify_signature_sets;
use proto_array::Block as ProtoBlock;
use slog::debug;
use slot_clock::SlotClock;
use state_processing::{
    common::get_indexed_attestation,
    per_block_processing::errors::AttestationValidationError,
    signature_sets::{
        indexed_attestation_signature_set_from_pubkeys,
        signed_aggregate_selection_proof_signature_set, signed_aggregate_signature_set,
    },
};
use std::borrow::Cow;
use strum::AsRefStr;
use tree_hash::TreeHash;
use types::{
    Attestation, BeaconCommittee, CommitteeIndex, Epoch, EthSpec, Hash256, IndexedAttestation,
    SelectionProof, SignedAggregateAndProof, Slot, SubnetId,
};

pub use batch::{batch_verify_aggregated_attestations, batch_verify_unaggregated_attestations};

/// Returned when an attestation was not successfully verified. It might not have been verified for
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
        attestation_slot: Slot,
        latest_permissible_slot: Slot,
    },
    /// The attestation is from a slot that is prior to the earliest permissible slot (with
    /// respect to the gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    PastSlot {
        attestation_slot: Slot,
        earliest_permissible_slot: Slot,
    },
    /// The attestations aggregation bits were empty when they shouldn't be.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    EmptyAggregationBitfield,
    /// The `selection_proof` on the aggregate attestation does not elect it as an aggregator.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidSelectionProof { aggregator_index: u64 },
    /// The `selection_proof` on the aggregate attestation selects it as a validator, however the
    /// aggregator index is not in the committee for that attestation.
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
    /// The `attestation.data.beacon_block_root` block is unknown.
    ///
    /// ## Peer scoring
    ///
    /// The attestation points to a block we have not yet imported. It's unclear if the attestation
    /// is valid or not.
    UnknownHeadBlock { beacon_block_root: Hash256 },
    /// The `attestation.data.slot` is not from the same epoch as `data.target.epoch`.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    BadTargetEpoch,
    /// The target root of the attestation points to a block that we have not verified.
    ///
    /// This is invalid behaviour whilst we first check for `UnknownHeadBlock`.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    UnknownTargetRoot(Hash256),
    /// A signature on the attestation is invalid.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidSignature,
    /// There is no committee for the slot and committee index of this attestation and the
    /// attestation should not have been produced.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    NoCommitteeForSlotAndIndex { slot: Slot, index: CommitteeIndex },
    /// The unaggregated attestation doesn't have only one aggregation bit set.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    NotExactlyOneAggregationBitSet(usize),
    /// We have already observed an attestation for the `validator_index` and refuse to process
    /// another.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this attestation is valid, however we have already observed a
    /// single-participant attestation from this validator for this epoch and should not observe
    /// another.
    PriorAttestationKnown { validator_index: u64, epoch: Epoch },
    /// The attestation is for an epoch in the future (with respect to the gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    FutureEpoch {
        attestation_epoch: Epoch,
        current_epoch: Epoch,
    },
    /// The attestation is for an epoch in the past (with respect to the gossip clock disparity).
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    PastEpoch {
        attestation_epoch: Epoch,
        current_epoch: Epoch,
    },
    /// The attestation is attesting to a state that is later than itself. (Viz., attesting to the
    /// future).
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    AttestsToFutureBlock { block: Slot, attestation: Slot },
    /// The attestation was received on an invalid attestation subnet.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidSubnetId {
        received: SubnetId,
        expected: SubnetId,
    },
    /// The attestation failed the `state_processing` verification stage.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    Invalid(AttestationValidationError),
    /// The attestation head block is too far behind the attestation slot, causing many skip slots.
    /// This is deemed a DoS risk.
    TooManySkippedSlots {
        head_block_slot: Slot,
        attestation_slot: Slot,
    },
    /// The attestation has an invalid target epoch.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidTargetEpoch { slot: Slot, epoch: Epoch },
    /// The attestation references an invalid target block.
    ///
    /// ## Peer scoring
    ///
    /// The peer has sent an invalid message.
    InvalidTargetRoot {
        attestation: Hash256,
        expected: Option<Hash256>,
    },
    /// There was an error whilst processing the attestation. It is not known if it is valid or invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this attestation due to an internal error. It's unclear if the
    /// attestation is valid.
    BeaconChainError(BeaconChainError),
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Self {
        Error::BeaconChainError(e)
    }
}

/// Used to avoid double-checking signatures.
#[derive(Copy, Clone)]
enum CheckAttestationSignature {
    Yes,
    No,
}

/// Wraps a `SignedAggregateAndProof` that has been verified up until the point that an
/// `IndexedAttestation` can be derived.
///
/// These attestations have *not* undergone signature verification.
struct IndexedAggregatedAttestation<'a, T: BeaconChainTypes> {
    signed_aggregate: &'a SignedAggregateAndProof<T::EthSpec>,
    indexed_attestation: IndexedAttestation<T::EthSpec>,
    attestation_root: Hash256,
}

/// Wraps a `Attestation` that has been verified up until the point that an `IndexedAttestation` can
/// be derived.
///
/// These attestations have *not* undergone signature verification.
struct IndexedUnaggregatedAttestation<'a, T: BeaconChainTypes> {
    attestation: &'a Attestation<T::EthSpec>,
    indexed_attestation: IndexedAttestation<T::EthSpec>,
    subnet_id: SubnetId,
    validator_index: u64,
}

/// Wraps a `SignedAggregateAndProof` that has been fully verified for propagation on the gossip
/// network.
pub struct VerifiedAggregatedAttestation<'a, T: BeaconChainTypes> {
    signed_aggregate: &'a SignedAggregateAndProof<T::EthSpec>,
    indexed_attestation: IndexedAttestation<T::EthSpec>,
}

impl<'a, T: BeaconChainTypes> VerifiedAggregatedAttestation<'a, T> {
    pub fn into_indexed_attestation(self) -> IndexedAttestation<T::EthSpec> {
        self.indexed_attestation
    }
}

/// Wraps an `Attestation` that has been fully verified for propagation on the gossip network.
pub struct VerifiedUnaggregatedAttestation<'a, T: BeaconChainTypes> {
    attestation: &'a Attestation<T::EthSpec>,
    indexed_attestation: IndexedAttestation<T::EthSpec>,
    subnet_id: SubnetId,
}

impl<'a, T: BeaconChainTypes> VerifiedUnaggregatedAttestation<'a, T> {
    pub fn into_indexed_attestation(self) -> IndexedAttestation<T::EthSpec> {
        self.indexed_attestation
    }
}

/// Custom `Clone` implementation is to avoid the restrictive trait bounds applied by the usual derive
/// macro.
impl<'a, T: BeaconChainTypes> Clone for IndexedUnaggregatedAttestation<'a, T> {
    fn clone(&self) -> Self {
        Self {
            attestation: self.attestation,
            indexed_attestation: self.indexed_attestation.clone(),
            subnet_id: self.subnet_id,
            validator_index: self.validator_index,
        }
    }
}

/// A helper trait implemented on wrapper types that can be progressed to a state where they can be
/// verified for application to fork choice.
pub trait VerifiedAttestation<T: BeaconChainTypes> {
    fn attestation(&self) -> &Attestation<T::EthSpec>;

    fn indexed_attestation(&self) -> &IndexedAttestation<T::EthSpec>;
}

impl<'a, T: BeaconChainTypes> VerifiedAttestation<T> for VerifiedAggregatedAttestation<'a, T> {
    fn attestation(&self) -> &Attestation<T::EthSpec> {
        self.attestation()
    }

    fn indexed_attestation(&self) -> &IndexedAttestation<T::EthSpec> {
        &self.indexed_attestation
    }
}

impl<'a, T: BeaconChainTypes> VerifiedAttestation<T> for VerifiedUnaggregatedAttestation<'a, T> {
    fn attestation(&self) -> &Attestation<T::EthSpec> {
        self.attestation
    }

    fn indexed_attestation(&self) -> &IndexedAttestation<T::EthSpec> {
        &self.indexed_attestation
    }
}

/// Information about invalid attestations which might still be slashable despite being invalid.
pub enum AttestationSlashInfo<'a, T: BeaconChainTypes, TErr> {
    /// The attestation is invalid, but its signature wasn't checked.
    SignatureNotChecked(&'a Attestation<T::EthSpec>, TErr),
    /// As for `SignatureNotChecked`, but we know the `IndexedAttestation`.
    SignatureNotCheckedIndexed(IndexedAttestation<T::EthSpec>, TErr),
    /// The attestation's signature is invalid, so it will never be slashable.
    SignatureInvalid(TErr),
    /// The signature is valid but the attestation is invalid in some other way.
    SignatureValid(IndexedAttestation<T::EthSpec>, TErr),
}

/// After processing an attestation normally, optionally process it further for the slasher.
///
/// This maps an `AttestationSlashInfo` error back into a regular `Error`, performing signature
/// checks on attestations that failed verification for other reasons.
///
/// No substantial extra work will be done if there is no slasher configured.
fn process_slash_info<T: BeaconChainTypes>(
    slash_info: AttestationSlashInfo<T, Error>,
    chain: &BeaconChain<T>,
) -> Error {
    use AttestationSlashInfo::*;

    if let Some(slasher) = chain.slasher.as_ref() {
        let (indexed_attestation, check_signature, err) = match slash_info {
            SignatureNotChecked(attestation, err) => {
                match obtain_indexed_attestation_and_committees_per_slot(chain, attestation) {
                    Ok((indexed, _)) => (indexed, true, err),
                    Err(e) => {
                        debug!(
                            chain.log,
                            "Unable to obtain indexed form of attestation for slasher";
                            "attestation_root" => format!("{:?}", attestation.tree_hash_root()),
                            "error" => format!("{:?}", e)
                        );
                        return err;
                    }
                }
            }
            SignatureNotCheckedIndexed(indexed, err) => (indexed, true, err),
            SignatureInvalid(e) => return e,
            SignatureValid(indexed, err) => (indexed, false, err),
        };

        if check_signature {
            if let Err(e) = verify_attestation_signature(chain, &indexed_attestation) {
                debug!(
                    chain.log,
                    "Signature verification for slasher failed";
                    "error" => format!("{:?}", e),
                );
                return err;
            }
        }

        // Supply to slasher.
        slasher.accept_attestation(indexed_attestation);

        err
    } else {
        match slash_info {
            SignatureNotChecked(_, e)
            | SignatureNotCheckedIndexed(_, e)
            | SignatureInvalid(e)
            | SignatureValid(_, e) => e,
        }
    }
}

impl<'a, T: BeaconChainTypes> IndexedAggregatedAttestation<'a, T> {
    /// Returns `Ok(Self)` if the `signed_aggregate` is valid to be (re)published on the gossip
    /// network.
    pub fn verify(
        signed_aggregate: &'a SignedAggregateAndProof<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        Self::verify_slashable(signed_aggregate, chain)
            .map(|verified_aggregate| {
                if let Some(slasher) = chain.slasher.as_ref() {
                    slasher.accept_attestation(verified_aggregate.indexed_attestation.clone());
                }
                verified_aggregate
            })
            .map_err(|slash_info| process_slash_info(slash_info, chain))
    }

    /// Run the checks that happen before an indexed attestation is constructed.
    fn verify_early_checks(
        signed_aggregate: &SignedAggregateAndProof<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Hash256, Error> {
        let attestation = &signed_aggregate.message.aggregate;

        // Ensure attestation is within the last ATTESTATION_PROPAGATION_SLOT_RANGE slots (within a
        // MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance).
        //
        // We do not queue future attestations for later processing.
        verify_propagation_slot_range(chain, attestation)?;

        // Check the attestation's epoch matches its target.
        if attestation.data.slot.epoch(T::EthSpec::slots_per_epoch())
            != attestation.data.target.epoch
        {
            return Err(Error::InvalidTargetEpoch {
                slot: attestation.data.slot,
                epoch: attestation.data.target.epoch,
            });
        }

        // Ensure the valid aggregated attestation has not already been seen locally.
        let attestation_root = attestation.tree_hash_root();
        if chain
            .observed_attestations
            .write()
            .is_known(attestation, attestation_root)
            .map_err(|e| Error::BeaconChainError(e.into()))?
        {
            return Err(Error::AttestationAlreadyKnown(attestation_root));
        }

        let aggregator_index = signed_aggregate.message.aggregator_index;

        // Ensure there has been no other observed aggregate for the given `aggregator_index`.
        //
        // Note: do not observe yet, only observe once the attestation has been verified.
        match chain
            .observed_aggregators
            .read()
            .validator_has_been_observed(attestation.data.target.epoch, aggregator_index as usize)
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
        let head_block = verify_head_block_is_known(chain, attestation, None)?;

        // Check the attestation target root is consistent with the head root.
        //
        // This check is not in the specification, however we guard against it since it opens us up
        // to weird edge cases during verification.
        //
        // Whilst this attestation *technically* could be used to add value to a block, it is
        // invalid in the spirit of the protocol. Here we choose safety over profit.
        verify_attestation_target_root::<T::EthSpec>(&head_block, attestation)?;

        // Ensure that the attestation has participants.
        if attestation.aggregation_bits.is_zero() {
            Err(Error::EmptyAggregationBitfield)
        } else {
            Ok(attestation_root)
        }
    }

    /// Verify the attestation, producing extra information about whether it might be slashable.
    pub fn verify_slashable(
        signed_aggregate: &'a SignedAggregateAndProof<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, AttestationSlashInfo<'a, T, Error>> {
        use AttestationSlashInfo::*;

        let attestation = &signed_aggregate.message.aggregate;
        let aggregator_index = signed_aggregate.message.aggregator_index;
        let attestation_root = match Self::verify_early_checks(signed_aggregate, chain) {
            Ok(root) => root,
            Err(e) => return Err(SignatureNotChecked(&signed_aggregate.message.aggregate, e)),
        };

        let indexed_attestation =
            match map_attestation_committee(chain, attestation, |(committee, _)| {
                // Note: this clones the signature which is known to be a relatively slow operation.
                //
                // Future optimizations should remove this clone.
                let selection_proof =
                    SelectionProof::from(signed_aggregate.message.selection_proof.clone());

                if !selection_proof
                    .is_aggregator(committee.committee.len(), &chain.spec)
                    .map_err(|e| Error::BeaconChainError(e.into()))?
                {
                    return Err(Error::InvalidSelectionProof { aggregator_index });
                }

                // Ensure the aggregator is a member of the committee for which it is aggregating.
                if !committee.committee.contains(&(aggregator_index as usize)) {
                    return Err(Error::AggregatorNotInCommittee { aggregator_index });
                }

                get_indexed_attestation(committee.committee, attestation)
                    .map_err(|e| BeaconChainError::from(e).into())
            }) {
                Ok(indexed_attestation) => indexed_attestation,
                Err(e) => return Err(SignatureNotChecked(&signed_aggregate.message.aggregate, e)),
            };

        Ok(IndexedAggregatedAttestation {
            signed_aggregate,
            indexed_attestation,
            attestation_root,
        })
    }
}

impl<'a, T: BeaconChainTypes> VerifiedAggregatedAttestation<'a, T> {
    /// Run the checks that happen after the indexed attestation and signature have been checked.
    fn verify_late_checks(
        signed_aggregate: &SignedAggregateAndProof<T::EthSpec>,
        attestation_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<(), Error> {
        let attestation = &signed_aggregate.message.aggregate;
        let aggregator_index = signed_aggregate.message.aggregator_index;

        // Observe the valid attestation so we do not re-process it.
        //
        // It's important to double check that the attestation is not already known, otherwise two
        // attestations processed at the same time could be published.
        if let ObserveOutcome::AlreadyKnown = chain
            .observed_attestations
            .write()
            .observe_item(attestation, Some(attestation_root))
            .map_err(|e| Error::BeaconChainError(e.into()))?
        {
            return Err(Error::AttestationAlreadyKnown(attestation_root));
        }

        // Observe the aggregator so we don't process another aggregate from them.
        //
        // It's important to double check that the attestation is not already known, otherwise two
        // attestations processed at the same time could be published.
        if chain
            .observed_aggregators
            .write()
            .observe_validator(attestation.data.target.epoch, aggregator_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorAttestationKnown {
                validator_index: aggregator_index,
                epoch: attestation.data.target.epoch,
            });
        }

        Ok(())
    }

    /// Verify the `signed_aggregate`.
    pub fn verify(
        signed_aggregate: &'a SignedAggregateAndProof<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        let indexed = IndexedAggregatedAttestation::verify(signed_aggregate, chain)?;
        Self::from_indexed(indexed, chain, CheckAttestationSignature::Yes)
    }

    /// Complete the verification of an indexed attestation.
    fn from_indexed(
        signed_aggregate: IndexedAggregatedAttestation<'a, T>,
        chain: &BeaconChain<T>,
        check_signature: CheckAttestationSignature,
    ) -> Result<Self, Error> {
        Self::verify_slashable(signed_aggregate, chain, check_signature)
            .map(|verified_aggregate| verified_aggregate.apply_to_slasher(chain))
            .map_err(|slash_info| process_slash_info(slash_info, chain))
    }

    fn apply_to_slasher(self, chain: &BeaconChain<T>) -> Self {
        if let Some(slasher) = chain.slasher.as_ref() {
            slasher.accept_attestation(self.indexed_attestation.clone());
        }
        self
    }

    /// Verify the attestation, producing extra information about whether it might be slashable.
    fn verify_slashable(
        signed_aggregate: IndexedAggregatedAttestation<'a, T>,
        chain: &BeaconChain<T>,
        check_signature: CheckAttestationSignature,
    ) -> Result<Self, AttestationSlashInfo<'a, T, Error>> {
        use AttestationSlashInfo::*;

        let IndexedAggregatedAttestation {
            signed_aggregate,
            indexed_attestation,
            attestation_root,
        } = signed_aggregate;

        match check_signature {
            CheckAttestationSignature::Yes => {
                // Ensure that all signatures are valid.
                if let Err(e) = verify_signed_aggregate_signatures(
                    chain,
                    signed_aggregate,
                    &indexed_attestation,
                )
                .and_then(|is_valid| {
                    if !is_valid {
                        Err(Error::InvalidSignature)
                    } else {
                        Ok(())
                    }
                }) {
                    return Err(SignatureInvalid(e));
                }
            }
            CheckAttestationSignature::No => (),
        };

        if let Err(e) = Self::verify_late_checks(signed_aggregate, attestation_root, chain) {
            return Err(SignatureValid(indexed_attestation, e));
        }

        Ok(VerifiedAggregatedAttestation {
            signed_aggregate,
            indexed_attestation,
        })
    }

    /// Returns the underlying `attestation` for the `signed_aggregate`.
    pub fn attestation(&self) -> &Attestation<T::EthSpec> {
        &self.signed_aggregate.message.aggregate
    }

    /// Returns the underlying `signed_aggregate`.
    pub fn aggregate(&self) -> &SignedAggregateAndProof<T::EthSpec> {
        self.signed_aggregate
    }
}

impl<'a, T: BeaconChainTypes> IndexedUnaggregatedAttestation<'a, T> {
    /// Run the checks that happen before an indexed attestation is constructed.
    pub fn verify_early_checks(
        attestation: &Attestation<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<(), Error> {
        let attestation_epoch = attestation.data.slot.epoch(T::EthSpec::slots_per_epoch());

        // Check the attestation's epoch matches its target.
        if attestation_epoch != attestation.data.target.epoch {
            return Err(Error::InvalidTargetEpoch {
                slot: attestation.data.slot,
                epoch: attestation.data.target.epoch,
            });
        }

        // Ensure attestation is within the last ATTESTATION_PROPAGATION_SLOT_RANGE slots (within a
        // MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance).
        //
        // We do not queue future attestations for later processing.
        verify_propagation_slot_range(chain, attestation)?;

        // Check to ensure that the attestation is "unaggregated". I.e., it has exactly one
        // aggregation bit set.
        let num_aggregation_bits = attestation.aggregation_bits.num_set_bits();
        if num_aggregation_bits != 1 {
            return Err(Error::NotExactlyOneAggregationBitSet(num_aggregation_bits));
        }

        // Attestations must be for a known block. If the block is unknown, we simply drop the
        // attestation and do not delay consideration for later.
        //
        // Enforce a maximum skip distance for unaggregated attestations.
        let head_block =
            verify_head_block_is_known(chain, attestation, chain.config.import_max_skip_slots)?;

        // Check the attestation target root is consistent with the head root.
        verify_attestation_target_root::<T::EthSpec>(&head_block, attestation)?;

        Ok(())
    }

    /// Run the checks that apply to the indexed attestation before the signature is checked.
    pub fn verify_middle_checks(
        attestation: &Attestation<T::EthSpec>,
        indexed_attestation: &IndexedAttestation<T::EthSpec>,
        committees_per_slot: u64,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<(u64, SubnetId), Error> {
        let expected_subnet_id = SubnetId::compute_subnet_for_attestation_data::<T::EthSpec>(
            &indexed_attestation.data,
            committees_per_slot,
            &chain.spec,
        )
        .map_err(BeaconChainError::from)?;

        // If a subnet was specified, ensure that subnet is correct.
        if let Some(subnet_id) = subnet_id {
            if subnet_id != expected_subnet_id {
                return Err(Error::InvalidSubnetId {
                    received: subnet_id,
                    expected: expected_subnet_id,
                });
            }
        };

        let validator_index = *indexed_attestation
            .attesting_indices
            .first()
            .ok_or(Error::NotExactlyOneAggregationBitSet(0))?;

        /*
         * The attestation is the first valid attestation received for the participating validator
         * for the slot, attestation.data.slot.
         */
        if chain
            .observed_gossip_attesters
            .read()
            .validator_has_been_observed(attestation.data.target.epoch, validator_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorAttestationKnown {
                validator_index,
                epoch: attestation.data.target.epoch,
            });
        }

        Ok((validator_index, expected_subnet_id))
    }

    /// Returns `Ok(Self)` if the `attestation` is valid to be (re)published on the gossip
    /// network.
    ///
    /// `subnet_id` is the subnet from which we received this attestation. This function will
    /// verify that it was received on the correct subnet.
    pub fn verify(
        attestation: &'a Attestation<T::EthSpec>,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        Self::verify_slashable(attestation, subnet_id, chain)
            .map(|verified_unaggregated| {
                if let Some(slasher) = chain.slasher.as_ref() {
                    slasher.accept_attestation(verified_unaggregated.indexed_attestation.clone());
                }
                verified_unaggregated
            })
            .map_err(|slash_info| process_slash_info(slash_info, chain))
    }

    /// Verify the attestation, producing extra information about whether it might be slashable.
    pub fn verify_slashable(
        attestation: &'a Attestation<T::EthSpec>,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, AttestationSlashInfo<'a, T, Error>> {
        use AttestationSlashInfo::*;

        if let Err(e) = Self::verify_early_checks(attestation, chain) {
            return Err(SignatureNotChecked(attestation, e));
        }

        let (indexed_attestation, committees_per_slot) =
            match obtain_indexed_attestation_and_committees_per_slot(chain, attestation) {
                Ok(x) => x,
                Err(e) => {
                    return Err(SignatureNotChecked(attestation, e));
                }
            };

        let (validator_index, expected_subnet_id) = match Self::verify_middle_checks(
            attestation,
            &indexed_attestation,
            committees_per_slot,
            subnet_id,
            chain,
        ) {
            Ok(t) => t,
            Err(e) => return Err(SignatureNotCheckedIndexed(indexed_attestation, e)),
        };

        Ok(Self {
            attestation,
            indexed_attestation,
            subnet_id: expected_subnet_id,
            validator_index,
        })
    }

    /// Returns a mutable reference to the underlying attestation.
    ///
    /// Only use during testing since modifying the `IndexedAttestation` can cause the attestation
    /// to no-longer be valid.
    pub fn __indexed_attestation_mut(&mut self) -> &mut IndexedAttestation<T::EthSpec> {
        &mut self.indexed_attestation
    }
}

impl<'a, T: BeaconChainTypes> VerifiedUnaggregatedAttestation<'a, T> {
    /// Run the checks that apply after the signature has been checked.
    fn verify_late_checks(
        attestation: &Attestation<T::EthSpec>,
        validator_index: u64,
        chain: &BeaconChain<T>,
    ) -> Result<(), Error> {
        // Now that the attestation has been fully verified, store that we have received a valid
        // attestation from this validator.
        //
        // It's important to double check that the attestation still hasn't been observed, since
        // there can be a race-condition if we receive two attestations at the same time and
        // process them in different threads.
        if chain
            .observed_gossip_attesters
            .write()
            .observe_validator(attestation.data.target.epoch, validator_index as usize)
            .map_err(BeaconChainError::from)?
        {
            return Err(Error::PriorAttestationKnown {
                validator_index,
                epoch: attestation.data.target.epoch,
            });
        }
        Ok(())
    }

    /// Verify the `unaggregated_attestation`.
    pub fn verify(
        unaggregated_attestation: &'a Attestation<T::EthSpec>,
        subnet_id: Option<SubnetId>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, Error> {
        let indexed =
            IndexedUnaggregatedAttestation::verify(unaggregated_attestation, subnet_id, chain)?;
        Self::from_indexed(indexed, chain, CheckAttestationSignature::Yes)
    }

    /// Complete the verification of an indexed attestation.
    fn from_indexed(
        attestation: IndexedUnaggregatedAttestation<'a, T>,
        chain: &BeaconChain<T>,
        check_signature: CheckAttestationSignature,
    ) -> Result<Self, Error> {
        Self::verify_slashable(attestation, chain, check_signature)
            .map(|verified_unaggregated| verified_unaggregated.apply_to_slasher(chain))
            .map_err(|slash_info| process_slash_info(slash_info, chain))
    }

    fn apply_to_slasher(self, chain: &BeaconChain<T>) -> Self {
        if let Some(slasher) = chain.slasher.as_ref() {
            slasher.accept_attestation(self.indexed_attestation.clone());
        }
        self
    }

    /// Verify the attestation, producing extra information about whether it might be slashable.
    fn verify_slashable(
        attestation: IndexedUnaggregatedAttestation<'a, T>,
        chain: &BeaconChain<T>,
        check_signature: CheckAttestationSignature,
    ) -> Result<Self, AttestationSlashInfo<'a, T, Error>> {
        use AttestationSlashInfo::*;

        let IndexedUnaggregatedAttestation {
            attestation,
            indexed_attestation,
            subnet_id,
            validator_index,
        } = attestation;

        match check_signature {
            CheckAttestationSignature::Yes => {
                if let Err(e) = verify_attestation_signature(chain, &indexed_attestation) {
                    return Err(SignatureInvalid(e));
                }
            }
            CheckAttestationSignature::No => (),
        };

        if let Err(e) = Self::verify_late_checks(attestation, validator_index, chain) {
            return Err(SignatureValid(indexed_attestation, e));
        }

        Ok(Self {
            attestation,
            indexed_attestation,
            subnet_id,
        })
    }

    /// Returns the correct subnet for the attestation.
    pub fn subnet_id(&self) -> SubnetId {
        self.subnet_id
    }

    /// Returns the wrapped `attestation`.
    pub fn attestation(&self) -> &Attestation<T::EthSpec> {
        self.attestation
    }

    /// Returns the wrapped `indexed_attestation`.
    pub fn indexed_attestation(&self) -> &IndexedAttestation<T::EthSpec> {
        &self.indexed_attestation
    }

    /// Returns a mutable reference to the underlying attestation.
    ///
    /// Only use during testing since modifying the `IndexedAttestation` can cause the attestation
    /// to no-longer be valid.
    pub fn __indexed_attestation_mut(&mut self) -> &mut IndexedAttestation<T::EthSpec> {
        &mut self.indexed_attestation
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
fn verify_head_block_is_known<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    attestation: &Attestation<T::EthSpec>,
    max_skip_slots: Option<u64>,
) -> Result<ProtoBlock, Error> {
    if let Some(block) = chain
        .fork_choice
        .read()
        .get_block(&attestation.data.beacon_block_root)
    {
        // Reject any block that exceeds our limit on skipped slots.
        if let Some(max_skip_slots) = max_skip_slots {
            if attestation.data.slot > block.slot + max_skip_slots {
                return Err(Error::TooManySkippedSlots {
                    head_block_slot: block.slot,
                    attestation_slot: attestation.data.slot,
                });
            }
        }

        Ok(block)
    } else {
        Err(Error::UnknownHeadBlock {
            beacon_block_root: attestation.data.beacon_block_root,
        })
    }
}

/// Verify that the `attestation` is within the acceptable gossip propagation range, with reference
/// to the current slot of the `chain`.
///
/// Accounts for `MAXIMUM_GOSSIP_CLOCK_DISPARITY`.
pub fn verify_propagation_slot_range<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    attestation: &Attestation<T::EthSpec>,
) -> Result<(), Error> {
    let attestation_slot = attestation.data.slot;

    let latest_permissible_slot = chain
        .slot_clock
        .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or(BeaconChainError::UnableToReadSlot)?;
    if attestation_slot > latest_permissible_slot {
        return Err(Error::FutureSlot {
            attestation_slot,
            latest_permissible_slot,
        });
    }

    // Taking advantage of saturating subtraction on `Slot`.
    let earliest_permissible_slot = chain
        .slot_clock
        .now_with_past_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
        .ok_or(BeaconChainError::UnableToReadSlot)?
        - T::EthSpec::slots_per_epoch();
    if attestation_slot < earliest_permissible_slot {
        return Err(Error::PastSlot {
            attestation_slot,
            earliest_permissible_slot,
        });
    }

    Ok(())
}

/// Verifies that the signature of the `indexed_attestation` is valid.
pub fn verify_attestation_signature<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    indexed_attestation: &IndexedAttestation<T::EthSpec>,
) -> Result<(), Error> {
    let signature_setup_timer =
        metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_SETUP_TIMES);

    let pubkey_cache = chain
        .validator_pubkey_cache
        .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
        .ok_or(BeaconChainError::ValidatorPubkeyCacheLockTimeout)?;

    let fork = chain
        .spec
        .fork_at_epoch(indexed_attestation.data.target.epoch);

    let signature_set = indexed_attestation_signature_set_from_pubkeys(
        |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
        &indexed_attestation.signature,
        indexed_attestation,
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

/// Verifies that the `attestation.data.target.root` is indeed the target root of the block at
/// `attestation.data.beacon_block_root`.
pub fn verify_attestation_target_root<T: EthSpec>(
    head_block: &ProtoBlock,
    attestation: &Attestation<T>,
) -> Result<(), Error> {
    // Check the attestation target root.
    let head_block_epoch = head_block.slot.epoch(T::slots_per_epoch());
    let attestation_epoch = attestation.data.slot.epoch(T::slots_per_epoch());
    if head_block_epoch > attestation_epoch {
        // The epoch references an invalid head block from a future epoch.
        //
        // This check is not in the specification, however we guard against it since it opens us up
        // to weird edge cases during verification.
        //
        // Whilst this attestation *technically* could be used to add value to a block, it is
        // invalid in the spirit of the protocol. Here we choose safety over profit.
        //
        // Reference:
        // https://github.com/ethereum/eth2.0-specs/pull/2001#issuecomment-699246659
        return Err(Error::InvalidTargetRoot {
            attestation: attestation.data.target.root,
            // It is not clear what root we should expect in this case, since the attestation is
            // fundamentally invalid.
            expected: None,
        });
    } else {
        let target_root = if head_block_epoch == attestation_epoch {
            // If the block is in the same epoch as the attestation, then use the target root
            // from the block.
            head_block.target_root
        } else {
            // If the head block is from a previous epoch then skip slots will cause the head block
            // root to become the target block root.
            //
            // We know the head block is from a previous epoch due to a previous check.
            head_block.root
        };

        // Reject any attestation with an invalid target root.
        if target_root != attestation.data.target.root {
            return Err(Error::InvalidTargetRoot {
                attestation: attestation.data.target.root,
                expected: Some(target_root),
            });
        }
    }

    Ok(())
}

/// Verifies all the signatures in a `SignedAggregateAndProof` using BLS batch verification. This
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
    signed_aggregate: &SignedAggregateAndProof<T::EthSpec>,
    indexed_attestation: &IndexedAttestation<T::EthSpec>,
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
        .spec
        .fork_at_epoch(indexed_attestation.data.target.epoch);

    let signature_sets = vec![
        signed_aggregate_selection_proof_signature_set(
            |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
            signed_aggregate,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
        .map_err(BeaconChainError::SignatureSetError)?,
        signed_aggregate_signature_set(
            |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
            signed_aggregate,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
        .map_err(BeaconChainError::SignatureSetError)?,
        indexed_attestation_signature_set_from_pubkeys(
            |validator_index| pubkey_cache.get(validator_index).map(Cow::Borrowed),
            &indexed_attestation.signature,
            indexed_attestation,
            &fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
        .map_err(BeaconChainError::SignatureSetError)?,
    ];

    Ok(verify_signature_sets(signature_sets.iter()))
}

/// Assists in readability.
type CommitteesPerSlot = u64;

/// Returns the `indexed_attestation` and committee count per slot for the `attestation` using the
/// public keys cached in the `chain`.
fn obtain_indexed_attestation_and_committees_per_slot<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    attestation: &Attestation<T::EthSpec>,
) -> Result<(IndexedAttestation<T::EthSpec>, CommitteesPerSlot), Error> {
    map_attestation_committee(chain, attestation, |(committee, committees_per_slot)| {
        get_indexed_attestation(committee.committee, attestation)
            .map(|attestation| (attestation, committees_per_slot))
            .map_err(Error::Invalid)
    })
}

/// Runs the `map_fn` with the committee and committee count per slot for the given `attestation`.
///
/// This function exists in this odd "map" pattern because efficiently obtaining the committee for
/// an attestation can be complex. It might involve reading straight from the
/// `beacon_chain.shuffling_cache` or it might involve reading it from a state from the DB. Due to
/// the complexities of `RwLock`s on the shuffling cache, a simple `Cow` isn't suitable here.
///
/// If the committee for `attestation` isn't found in the `shuffling_cache`, we will read a state
/// from disk and then update the `shuffling_cache`.
fn map_attestation_committee<T, F, R>(
    chain: &BeaconChain<T>,
    attestation: &Attestation<T::EthSpec>,
    map_fn: F,
) -> Result<R, Error>
where
    T: BeaconChainTypes,
    F: Fn((BeaconCommittee, CommitteesPerSlot)) -> Result<R, Error>,
{
    let attestation_epoch = attestation.data.slot.epoch(T::EthSpec::slots_per_epoch());
    let target = &attestation.data.target;

    // Attestation target must be for a known block.
    //
    // We use fork choice to find the target root, which means that we reject any attestation
    // that has a `target.root` earlier than our latest finalized root. There's no point in
    // processing an attestation that does not include our latest finalized block in its chain.
    //
    // We do not delay consideration for later, we simply drop the attestation.
    if !chain.fork_choice.read().contains_block(&target.root) {
        return Err(Error::UnknownTargetRoot(target.root));
    }

    chain
        .with_committee_cache(target.root, attestation_epoch, |committee_cache, _| {
            let committees_per_slot = committee_cache.committees_per_slot();

            Ok(committee_cache
                .get_beacon_committee(attestation.data.slot, attestation.data.index)
                .map(|committee| map_fn((committee, committees_per_slot)))
                .unwrap_or_else(|| {
                    Err(Error::NoCommitteeForSlotAndIndex {
                        slot: attestation.data.slot,
                        index: attestation.data.index,
                    })
                }))
        })
        .map_err(BeaconChainError::from)?
}
