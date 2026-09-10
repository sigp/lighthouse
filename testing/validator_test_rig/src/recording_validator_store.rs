use bls::{PublicKeyBytes, Signature};
use eth2::types::{RequestAuth, SignedRequestAuth};
use futures::Stream;
use std::sync::{Arc, Mutex};
use types::{
    Address, Epoch, ExecutionPayloadEnvelope, Graffiti, Hash256, PayloadAttestationData,
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

/// The arguments a service passed to `ValidatorStore::sign_block`.
#[derive(Debug, Clone)]
pub struct SignBlockCall {
    pub validator_pubkey: PublicKeyBytes,
    pub block_root: Hash256,
    pub local_payload_root: Option<Hash256>,
}

/// A `ValidatorStore` that delegates to `inner` and records the `sign_block` calls it receives.
pub struct RecordingValidatorStore<S> {
    inner: Arc<S>,
    sign_block_calls: Mutex<Vec<SignBlockCall>>,
}

impl<S> RecordingValidatorStore<S> {
    pub fn new(inner: Arc<S>) -> Self {
        Self {
            inner,
            sign_block_calls: Mutex::new(Vec::new()),
        }
    }

    pub fn sign_block_calls(&self) -> Vec<SignBlockCall> {
        self.sign_block_calls.lock().unwrap().clone()
    }
}

impl<S: ValidatorStore + 'static> ValidatorStore for RecordingValidatorStore<S> {
    type Error = S::Error;
    type E = S::E;

    fn validator_index(&self, pubkey: &PublicKeyBytes) -> Option<u64> {
        self.inner.validator_index(pubkey)
    }

    fn voting_pubkeys<I, F>(&self, filter_func: F) -> I
    where
        I: FromIterator<PublicKeyBytes>,
        F: Fn(DoppelgangerStatus) -> Option<PublicKeyBytes>,
    {
        self.inner.voting_pubkeys(filter_func)
    }

    fn doppelganger_protection_allows_signing(&self, validator_pubkey: PublicKeyBytes) -> bool {
        self.inner
            .doppelganger_protection_allows_signing(validator_pubkey)
    }

    fn num_voting_validators(&self) -> usize {
        self.inner.num_voting_validators()
    }

    fn graffiti(&self, validator_pubkey: &PublicKeyBytes) -> Option<Graffiti> {
        self.inner.graffiti(validator_pubkey)
    }

    fn get_fee_recipient(&self, validator_pubkey: &PublicKeyBytes) -> Option<Address> {
        self.inner.get_fee_recipient(validator_pubkey)
    }

    fn determine_builder_boost_factor(&self, validator_pubkey: &PublicKeyBytes) -> Option<u64> {
        self.inner.determine_builder_boost_factor(validator_pubkey)
    }

    async fn randao_reveal(
        &self,
        validator_pubkey: PublicKeyBytes,
        signing_epoch: Epoch,
    ) -> Result<Signature, StoreError<Self::Error>> {
        self.inner
            .randao_reveal(validator_pubkey, signing_epoch)
            .await
    }

    fn set_validator_index(&self, validator_pubkey: &PublicKeyBytes, index: u64) {
        self.inner.set_validator_index(validator_pubkey, index)
    }

    async fn sign_block(
        &self,
        validator_pubkey: PublicKeyBytes,
        block: UnsignedBlock<Self::E>,
        current_slot: Slot,
        local_payload_root: Option<Hash256>,
    ) -> Result<SignedBlock<Self::E>, StoreError<Self::Error>> {
        self.sign_block_calls.lock().unwrap().push(SignBlockCall {
            validator_pubkey,
            block_root: block.block_root(),
            local_payload_root,
        });
        self.inner
            .sign_block(validator_pubkey, block, current_slot, local_payload_root)
            .await
    }

    fn sign_attestations(
        self: &Arc<Self>,
        attestations: Vec<AttestationToSign>,
    ) -> impl Stream<Item = Result<Vec<SingleAttestation>, StoreError<Self::Error>>> + Send {
        self.inner.sign_attestations(attestations)
    }

    async fn sign_validator_registration_data(
        &self,
        validator_registration_data: ValidatorRegistrationData,
    ) -> Result<SignedValidatorRegistrationData, StoreError<Self::Error>> {
        self.inner
            .sign_validator_registration_data(validator_registration_data)
            .await
    }

    async fn produce_selection_proof(
        &self,
        validator_pubkey: PublicKeyBytes,
        slot: Slot,
    ) -> Result<SelectionProof, StoreError<Self::Error>> {
        self.inner
            .produce_selection_proof(validator_pubkey, slot)
            .await
    }

    async fn produce_sync_selection_proof(
        &self,
        validator_pubkey: &PublicKeyBytes,
        slot: Slot,
        subnet_id: SyncSubnetId,
    ) -> Result<SyncSelectionProof, StoreError<Self::Error>> {
        self.inner
            .produce_sync_selection_proof(validator_pubkey, slot, subnet_id)
            .await
    }

    fn sign_aggregate_and_proofs(
        self: &Arc<Self>,
        aggregates: Vec<AggregateToSign<Self::E>>,
    ) -> impl Stream<Item = Result<Vec<SignedAggregateAndProof<Self::E>>, StoreError<Self::Error>>> + Send
    {
        self.inner.sign_aggregate_and_proofs(aggregates)
    }

    fn sign_sync_committee_signatures(
        self: &Arc<Self>,
        messages: Vec<SyncMessageToSign>,
    ) -> impl Stream<Item = Result<Vec<SyncCommitteeMessage>, StoreError<Self::Error>>> + Send {
        self.inner.sign_sync_committee_signatures(messages)
    }

    fn sign_sync_committee_contributions(
        self: &Arc<Self>,
        contributions: Vec<ContributionToSign<Self::E>>,
    ) -> impl Stream<
        Item = Result<Vec<SignedContributionAndProof<Self::E>>, StoreError<Self::Error>>,
    > + Send {
        self.inner.sign_sync_committee_contributions(contributions)
    }

    fn prune_slashing_protection_db(&self, current_epoch: Epoch, first_run: bool) {
        self.inner
            .prune_slashing_protection_db(current_epoch, first_run)
    }

    async fn sign_execution_payload_envelope(
        &self,
        validator_pubkey: PublicKeyBytes,
        envelope: ExecutionPayloadEnvelope<Self::E>,
    ) -> Result<SignedExecutionPayloadEnvelope<Self::E>, StoreError<Self::Error>> {
        self.inner
            .sign_execution_payload_envelope(validator_pubkey, envelope)
            .await
    }

    async fn sign_payload_attestation(
        &self,
        validator_pubkey: PublicKeyBytes,
        data: PayloadAttestationData,
    ) -> Result<PayloadAttestationMessage, StoreError<Self::Error>> {
        self.inner
            .sign_payload_attestation(validator_pubkey, data)
            .await
    }

    async fn sign_proposer_preferences(
        &self,
        validator_pubkey: PublicKeyBytes,
        preferences: ProposerPreferences,
    ) -> Result<SignedProposerPreferences, StoreError<Self::Error>> {
        self.inner
            .sign_proposer_preferences(validator_pubkey, preferences)
            .await
    }

    async fn sign_request_auth_v1(
        &self,
        validator_pubkey: PublicKeyBytes,
        request_auth_v1: RequestAuth,
    ) -> Result<SignedRequestAuth, StoreError<Self::Error>> {
        self.inner
            .sign_request_auth_v1(validator_pubkey, request_auth_v1)
            .await
    }

    fn proposal_data(&self, pubkey: &PublicKeyBytes) -> Option<ProposalData> {
        self.inner.proposal_data(pubkey)
    }
}
