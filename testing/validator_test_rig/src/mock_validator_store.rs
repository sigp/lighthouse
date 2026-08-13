use bls::{PublicKeyBytes, Signature};
use eth2::types::{RequestAuth, SignedRequestAuth};
use futures::future::{BoxFuture, FutureExt};
use futures::{Stream, stream};
use std::future::Future;
use std::sync::Arc;
use types::{
    Address, Epoch, ExecutionPayloadEnvelope, Graffiti, MainnetEthSpec, PayloadAttestationData,
    PayloadAttestationMessage, ProposerPreferences, SelectionProof, SignedAggregateAndProof,
    SignedContributionAndProof, SignedExecutionPayloadEnvelope, SignedProposerPreferences,
    SignedValidatorRegistrationData, SingleAttestation, Slot, SyncCommitteeMessage,
    SyncSelectionProof, SyncSubnetId, ValidatorRegistrationData,
};
use validator_store::{
    AggregateToSign, AttestationToSign, ContributionToSign, DoppelgangerStatus,
    Error as StoreError, ProposalData, SignedBlock, SyncMessageToSign, UnsignedBlock,
    ValidatorStore,
};

type SignPayloadAttestationFn = Box<
    dyn Fn(
            PublicKeyBytes,
            PayloadAttestationData,
        ) -> BoxFuture<'static, Result<PayloadAttestationMessage, StoreError<()>>>
        + Send
        + Sync,
>;

/// A `ValidatorStore` test double for driving validator services without keystores.
///
/// Methods without a hook panic, so a test only exercises the calls it explicitly expects.
pub struct MockValidatorStore {
    sign_payload_attestation: SignPayloadAttestationFn,
}

impl MockValidatorStore {
    pub fn with_sign_payload_attestation<F, Fut>(hook: F) -> Self
    where
        F: Fn(PublicKeyBytes, PayloadAttestationData) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<PayloadAttestationMessage, StoreError<()>>> + Send + 'static,
    {
        Self {
            sign_payload_attestation: Box::new(move |pubkey, data| hook(pubkey, data).boxed()),
        }
    }
}

impl ValidatorStore for MockValidatorStore {
    type Error = ();
    type E = MainnetEthSpec;

    async fn sign_payload_attestation(
        &self,
        validator_pubkey: PublicKeyBytes,
        data: PayloadAttestationData,
    ) -> Result<PayloadAttestationMessage, StoreError<Self::Error>> {
        (self.sign_payload_attestation)(validator_pubkey, data).await
    }

    fn validator_index(&self, _pubkey: &PublicKeyBytes) -> Option<u64> {
        panic!("MockValidatorStore::validator_index called without a hook")
    }

    fn voting_pubkeys<I, F>(&self, _filter_func: F) -> I
    where
        I: FromIterator<PublicKeyBytes>,
        F: Fn(DoppelgangerStatus) -> Option<PublicKeyBytes>,
    {
        panic!("MockValidatorStore::voting_pubkeys called without a hook")
    }

    fn doppelganger_protection_allows_signing(&self, _validator_pubkey: PublicKeyBytes) -> bool {
        panic!("MockValidatorStore::doppelganger_protection_allows_signing called without a hook")
    }

    fn num_voting_validators(&self) -> usize {
        panic!("MockValidatorStore::num_voting_validators called without a hook")
    }

    fn graffiti(&self, _validator_pubkey: &PublicKeyBytes) -> Option<Graffiti> {
        panic!("MockValidatorStore::graffiti called without a hook")
    }

    fn get_fee_recipient(&self, _validator_pubkey: &PublicKeyBytes) -> Option<Address> {
        panic!("MockValidatorStore::get_fee_recipient called without a hook")
    }

    fn determine_builder_boost_factor(&self, _validator_pubkey: &PublicKeyBytes) -> Option<u64> {
        panic!("MockValidatorStore::determine_builder_boost_factor called without a hook")
    }

    async fn randao_reveal(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _signing_epoch: Epoch,
    ) -> Result<Signature, StoreError<Self::Error>> {
        panic!("MockValidatorStore::randao_reveal called without a hook")
    }

    fn set_validator_index(&self, _validator_pubkey: &PublicKeyBytes, _index: u64) {
        panic!("MockValidatorStore::set_validator_index called without a hook")
    }

    async fn sign_block(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _block: UnsignedBlock<Self::E>,
        _current_slot: Slot,
    ) -> Result<SignedBlock<Self::E>, StoreError<Self::Error>> {
        panic!("MockValidatorStore::sign_block called without a hook")
    }

    fn sign_attestations(
        self: &Arc<Self>,
        _attestations: Vec<AttestationToSign>,
    ) -> impl Stream<Item = Result<Vec<SingleAttestation>, StoreError<Self::Error>>> + Send {
        stream::empty()
    }

    async fn sign_validator_registration_data(
        &self,
        _validator_registration_data: ValidatorRegistrationData,
    ) -> Result<SignedValidatorRegistrationData, StoreError<Self::Error>> {
        panic!("MockValidatorStore::sign_validator_registration_data called without a hook")
    }

    async fn produce_selection_proof(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _slot: Slot,
    ) -> Result<SelectionProof, StoreError<Self::Error>> {
        panic!("MockValidatorStore::produce_selection_proof called without a hook")
    }

    async fn produce_sync_selection_proof(
        &self,
        _validator_pubkey: &PublicKeyBytes,
        _slot: Slot,
        _subnet_id: SyncSubnetId,
    ) -> Result<SyncSelectionProof, StoreError<Self::Error>> {
        panic!("MockValidatorStore::produce_sync_selection_proof called without a hook")
    }

    fn sign_aggregate_and_proofs(
        self: &Arc<Self>,
        _aggregates: Vec<AggregateToSign<Self::E>>,
    ) -> impl Stream<Item = Result<Vec<SignedAggregateAndProof<Self::E>>, StoreError<Self::Error>>> + Send
    {
        stream::empty()
    }

    fn sign_sync_committee_signatures(
        self: &Arc<Self>,
        _messages: Vec<SyncMessageToSign>,
    ) -> impl Stream<Item = Result<Vec<SyncCommitteeMessage>, StoreError<Self::Error>>> + Send {
        stream::empty()
    }

    fn sign_sync_committee_contributions(
        self: &Arc<Self>,
        _contributions: Vec<ContributionToSign<Self::E>>,
    ) -> impl Stream<
        Item = Result<Vec<SignedContributionAndProof<Self::E>>, StoreError<Self::Error>>,
    > + Send {
        stream::empty()
    }

    fn prune_slashing_protection_db(&self, _current_epoch: Epoch, _first_run: bool) {
        panic!("MockValidatorStore::prune_slashing_protection_db called without a hook")
    }

    async fn sign_execution_payload_envelope(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _envelope: ExecutionPayloadEnvelope<Self::E>,
    ) -> Result<SignedExecutionPayloadEnvelope<Self::E>, StoreError<Self::Error>> {
        panic!("MockValidatorStore::sign_execution_payload_envelope called without a hook")
    }

    async fn sign_proposer_preferences(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _preferences: ProposerPreferences,
    ) -> Result<SignedProposerPreferences, StoreError<Self::Error>> {
        panic!("MockValidatorStore::sign_proposer_preferences called without a hook")
    }

    async fn sign_request_auth_v1(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _request_auth_v1: RequestAuth,
    ) -> Result<SignedRequestAuth, StoreError<Self::Error>> {
        panic!("MockValidatorStore::sign_request_auth_v1 called without a hook")
    }

    fn proposal_data(&self, _pubkey: &PublicKeyBytes) -> Option<ProposalData> {
        panic!("MockValidatorStore::proposal_data called without a hook")
    }
}
