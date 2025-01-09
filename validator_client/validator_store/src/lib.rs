use slashing_protection::NotSafe;
use std::fmt::Debug;
use std::future::Future;
use types::{
    Address, Attestation, AttestationError, BeaconBlock, BlindedBeaconBlock, Epoch, EthSpec,
    Graffiti, Hash256, PublicKeyBytes, SelectionProof, Signature, SignedAggregateAndProof,
    SignedBeaconBlock, SignedBlindedBeaconBlock, SignedContributionAndProof,
    SignedValidatorRegistrationData, SignedVoluntaryExit, Slot, SyncCommitteeContribution,
    SyncCommitteeMessage, SyncSelectionProof, SyncSubnetId, ValidatorRegistrationData,
    VoluntaryExit,
};

#[derive(Debug, PartialEq, Clone)]
pub enum Error<T> {
    DoppelgangerProtected(PublicKeyBytes),
    UnknownToDoppelgangerService(PublicKeyBytes),
    UnknownPubkey(PublicKeyBytes),
    Slashable(NotSafe),
    SameData,
    GreaterThanCurrentSlot { slot: Slot, current_slot: Slot },
    GreaterThanCurrentEpoch { epoch: Epoch, current_epoch: Epoch },
    UnableToSignAttestation(AttestationError),
    SpecificError(T),
}

impl<T> From<T> for Error<T> {
    fn from(e: T) -> Self {
        Error::SpecificError(e)
    }
}

/// A helper struct, used for passing data from the validator store to services.
pub struct ProposalData {
    pub validator_index: Option<u64>,
    pub fee_recipient: Option<Address>,
    pub gas_limit: u64,
    pub builder_proposals: bool,
}

pub trait ValidatorStore: Send + Sync {
    type Error: Debug + Send + Sync;
    type E: EthSpec;

    /// Attempts to resolve the pubkey to a validator index.
    ///
    /// It may return `None` if the `pubkey` is:
    ///
    /// - Unknown.
    /// - Known, but with an unknown index.
    fn validator_index(&self, pubkey: &PublicKeyBytes) -> Option<u64>;

    /// Returns all voting pubkeys for all enabled validators.
    ///
    /// The `filter_func` allows for filtering pubkeys based upon their `DoppelgangerStatus`. There
    /// are two primary functions used here:
    ///
    /// - `DoppelgangerStatus::only_safe`: only returns pubkeys which have passed doppelganger
    ///     protection and are safe-enough to sign messages.
    /// - `DoppelgangerStatus::ignored`: returns all the pubkeys from `only_safe` *plus* those still
    ///     undergoing protection. This is useful for collecting duties or other non-signing tasks.
    fn voting_pubkeys<I, F>(&self, filter_func: F) -> I
    where
        I: FromIterator<PublicKeyBytes>,
        F: Fn(DoppelgangerStatus) -> Option<PublicKeyBytes>;

    /// Check if the `validator_pubkey` is permitted by the doppleganger protection to sign
    /// messages.
    fn doppelganger_protection_allows_signing(&self, validator_pubkey: PublicKeyBytes) -> bool;

    fn num_voting_validators(&self) -> usize;
    fn graffiti(&self, validator_pubkey: &PublicKeyBytes) -> Option<Graffiti>;

    /// Returns the fee recipient for the given public key. The priority order for fetching
    /// the fee recipient is:
    /// 1. validator_definitions.yml
    /// 2. process level fee recipient
    fn get_fee_recipient(&self, validator_pubkey: &PublicKeyBytes) -> Option<Address>;

    /// Translate the `builder_proposals`, `builder_boost_factor` and
    /// `prefer_builder_proposals` to a boost factor, if available.
    /// - If `prefer_builder_proposals` is true, set boost factor to `u64::MAX` to indicate a
    ///   preference for builder payloads.
    /// - If `builder_boost_factor` is a value other than None, return its value as the boost factor.
    /// - If `builder_proposals` is set to false, set boost factor to 0 to indicate a preference for
    ///   local payloads.
    /// - Else return `None` to indicate no preference between builder and local payloads.
    fn determine_builder_boost_factor(&self, validator_pubkey: &PublicKeyBytes) -> Option<u64>;

    fn randao_reveal(
        &self,
        validator_pubkey: PublicKeyBytes,
        signing_epoch: Epoch,
    ) -> impl Future<Output = Result<Signature, Error<Self::Error>>> + Send;

    fn set_validator_index(&self, validator_pubkey: &PublicKeyBytes, index: u64);

    fn sign_block(
        &self,
        validator_pubkey: PublicKeyBytes,
        block: UnsignedBlock<Self::E>,
        current_slot: Slot,
    ) -> impl Future<Output = Result<SignedBlock<Self::E>, Error<Self::Error>>> + Send;

    fn sign_attestation(
        &self,
        validator_pubkey: PublicKeyBytes,
        validator_committee_position: usize,
        attestation: &mut Attestation<Self::E>,
        current_epoch: Epoch,
    ) -> impl Future<Output = Result<(), Error<Self::Error>>> + Send;

    fn sign_voluntary_exit(
        &self,
        validator_pubkey: PublicKeyBytes,
        voluntary_exit: VoluntaryExit,
    ) -> impl Future<Output = Result<SignedVoluntaryExit, Error<Self::Error>>> + Send;

    fn sign_validator_registration_data(
        &self,
        validator_registration_data: ValidatorRegistrationData,
    ) -> impl Future<Output = Result<SignedValidatorRegistrationData, Error<Self::Error>>> + Send;

    /// Signs an `AggregateAndProof` for a given validator.
    ///
    /// The resulting `SignedAggregateAndProof` is sent on the aggregation channel and cannot be
    /// modified by actors other than the signing validator.
    fn produce_signed_aggregate_and_proof(
        &self,
        validator_pubkey: PublicKeyBytes,
        aggregator_index: u64,
        aggregate: Attestation<Self::E>,
        selection_proof: SelectionProof,
    ) -> impl Future<Output = Result<SignedAggregateAndProof<Self::E>, Error<Self::Error>>> + Send;

    /// Produces a `SelectionProof` for the `slot`, signed by with corresponding secret key to
    /// `validator_pubkey`.
    fn produce_selection_proof(
        &self,
        validator_pubkey: PublicKeyBytes,
        slot: Slot,
    ) -> impl Future<Output = Result<SelectionProof, Error<Self::Error>>> + Send;

    /// Produce a `SyncSelectionProof` for `slot` signed by the secret key of `validator_pubkey`.
    fn produce_sync_selection_proof(
        &self,
        validator_pubkey: &PublicKeyBytes,
        slot: Slot,
        subnet_id: SyncSubnetId,
    ) -> impl Future<Output = Result<SyncSelectionProof, Error<Self::Error>>> + Send;

    fn produce_sync_committee_signature(
        &self,
        slot: Slot,
        beacon_block_root: Hash256,
        validator_index: u64,
        validator_pubkey: &PublicKeyBytes,
    ) -> impl Future<Output = Result<SyncCommitteeMessage, Error<Self::Error>>> + Send;

    fn produce_signed_contribution_and_proof(
        &self,
        aggregator_index: u64,
        aggregator_pubkey: PublicKeyBytes,
        contribution: SyncCommitteeContribution<Self::E>,
        selection_proof: SyncSelectionProof,
    ) -> impl Future<Output = Result<SignedContributionAndProof<Self::E>, Error<Self::Error>>> + Send;

    /// Prune the slashing protection database so that it remains performant.
    ///
    /// This function will only do actual pruning periodically, so it should usually be
    /// cheap to call. The `first_run` flag can be used to print a more verbose message when pruning
    /// runs.
    fn prune_slashing_protection_db(&self, current_epoch: Epoch, first_run: bool);

    /// Returns `ProposalData` for the provided `pubkey` if it exists in `InitializedValidators`.
    /// `ProposalData` fields include defaulting logic described in `get_fee_recipient_defaulting`,
    /// `get_gas_limit_defaulting`, and `get_builder_proposals_defaulting`.
    fn proposal_data(&self, pubkey: &PublicKeyBytes) -> Option<ProposalData>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum UnsignedBlock<E: EthSpec> {
    Full(BeaconBlock<E>),
    Blinded(BlindedBeaconBlock<E>),
}

impl<E: EthSpec> From<BeaconBlock<E>> for UnsignedBlock<E> {
    fn from(block: BeaconBlock<E>) -> Self {
        UnsignedBlock::Full(block)
    }
}

impl<E: EthSpec> From<BlindedBeaconBlock<E>> for UnsignedBlock<E> {
    fn from(block: BlindedBeaconBlock<E>) -> Self {
        UnsignedBlock::Blinded(block)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SignedBlock<E: EthSpec> {
    Full(SignedBeaconBlock<E>),
    Blinded(SignedBlindedBeaconBlock<E>),
}

impl<E: EthSpec> From<SignedBeaconBlock<E>> for SignedBlock<E> {
    fn from(block: SignedBeaconBlock<E>) -> Self {
        SignedBlock::Full(block)
    }
}

impl<E: EthSpec> From<SignedBlindedBeaconBlock<E>> for SignedBlock<E> {
    fn from(block: SignedBlindedBeaconBlock<E>) -> Self {
        SignedBlock::Blinded(block)
    }
}

/// A wrapper around `PublicKeyBytes` which encodes information about the status of a validator
/// pubkey with regards to doppelganger protection.
#[derive(Debug, PartialEq)]
pub enum DoppelgangerStatus {
    /// Doppelganger protection has approved this for signing.
    ///
    /// This is because the service has waited some period of time to
    /// detect other instances of this key on the network.
    SigningEnabled(PublicKeyBytes),
    /// Doppelganger protection is still waiting to detect other instances.
    ///
    /// Do not use this pubkey for signing slashable messages!!
    ///
    /// However, it can safely be used for other non-slashable operations (e.g., collecting duties
    /// or subscribing to subnets).
    SigningDisabled(PublicKeyBytes),
    /// This pubkey is unknown to the doppelganger service.
    ///
    /// This represents a serious internal error in the program. This validator will be permanently
    /// disabled!
    UnknownToDoppelganger(PublicKeyBytes),
}

impl DoppelgangerStatus {
    /// Only return a pubkey if it is explicitly safe for doppelganger protection.
    ///
    /// If `Some(pubkey)` is returned, doppelganger has declared it safe for signing.
    ///
    /// ## Note
    ///
    /// "Safe" is only best-effort by doppelganger. There is no guarantee that a doppelganger
    /// doesn't exist.
    pub fn only_safe(self) -> Option<PublicKeyBytes> {
        match self {
            DoppelgangerStatus::SigningEnabled(pubkey) => Some(pubkey),
            DoppelgangerStatus::SigningDisabled(_) => None,
            DoppelgangerStatus::UnknownToDoppelganger(_) => None,
        }
    }

    /// Returns a key regardless of whether or not doppelganger has approved it. Such a key might be
    /// used for signing non-slashable messages, duties collection or other activities.
    ///
    /// If the validator is unknown to doppelganger then `None` will be returned.
    pub fn ignored(self) -> Option<PublicKeyBytes> {
        match self {
            DoppelgangerStatus::SigningEnabled(pubkey) => Some(pubkey),
            DoppelgangerStatus::SigningDisabled(pubkey) => Some(pubkey),
            DoppelgangerStatus::UnknownToDoppelganger(_) => None,
        }
    }

    /// Only return a pubkey if it will not be used for signing due to doppelganger detection.
    pub fn only_unsafe(self) -> Option<PublicKeyBytes> {
        match self {
            DoppelgangerStatus::SigningEnabled(_) => None,
            DoppelgangerStatus::SigningDisabled(pubkey) => Some(pubkey),
            DoppelgangerStatus::UnknownToDoppelganger(pubkey) => Some(pubkey),
        }
    }
}
