use bls::{Keypair, PublicKeyBytes, Signature};
use futures::Stream;
use std::sync::Arc;
use types::{
    Epoch, Hash256, MainnetEthSpec, PayloadAttestationData, PayloadAttestationMessage, Slot,
};
use validator_store::{
    AggregateToSign, AttestationToSign, ContributionToSign, DoppelgangerStatus, ProposalData,
    SignedBlock, SyncMessageToSign, UnsignedBlock,
};

type E = MainnetEthSpec;

pub struct MockValidatorStore {
    pub pubkey: PublicKeyBytes,
    pub validator_index: u64,
    keypair: Keypair,
}

impl MockValidatorStore {
    pub fn new(validator_index: u64) -> Self {
        let keypair = Keypair::random();
        let pubkey = PublicKeyBytes::from(keypair.pk.clone());
        Self {
            pubkey,
            validator_index,
            keypair,
        }
    }
}

impl validator_store::ValidatorStore for MockValidatorStore {
    type Error = String;
    type E = E;

    fn validator_index(&self, _pubkey: &PublicKeyBytes) -> Option<u64> {
        Some(self.validator_index)
    }

    fn voting_pubkeys<I, F>(&self, filter_func: F) -> I
    where
        I: FromIterator<PublicKeyBytes>,
        F: Fn(DoppelgangerStatus) -> Option<PublicKeyBytes>,
    {
        std::iter::once(filter_func(DoppelgangerStatus::SigningEnabled(self.pubkey)))
            .flatten()
            .collect()
    }

    fn doppelganger_protection_allows_signing(&self, _validator_pubkey: PublicKeyBytes) -> bool {
        true
    }

    fn num_voting_validators(&self) -> usize {
        1
    }

    fn graffiti(&self, _validator_pubkey: &PublicKeyBytes) -> Option<types::Graffiti> {
        None
    }

    fn get_fee_recipient(&self, _validator_pubkey: &PublicKeyBytes) -> Option<types::Address> {
        None
    }

    fn determine_builder_boost_factor(&self, _validator_pubkey: &PublicKeyBytes) -> Option<u64> {
        None
    }

    async fn randao_reveal(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _signing_epoch: Epoch,
    ) -> Result<Signature, validator_store::Error<Self::Error>> {
        unimplemented!()
    }

    fn set_validator_index(&self, _validator_pubkey: &PublicKeyBytes, _index: u64) {}

    async fn sign_block(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _block: UnsignedBlock<Self::E>,
        _current_slot: Slot,
    ) -> Result<SignedBlock<Self::E>, validator_store::Error<Self::Error>> {
        unimplemented!()
    }

    fn sign_attestations(
        self: &Arc<Self>,
        _attestations: Vec<AttestationToSign<Self::E>>,
    ) -> impl Stream<
        Item = Result<Vec<(u64, types::Attestation<Self::E>)>, validator_store::Error<Self::Error>>,
    > + Send {
        futures::stream::empty()
    }

    async fn sign_validator_registration_data(
        &self,
        _data: types::ValidatorRegistrationData,
    ) -> Result<types::SignedValidatorRegistrationData, validator_store::Error<Self::Error>> {
        unimplemented!()
    }

    async fn produce_selection_proof(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _slot: Slot,
    ) -> Result<types::SelectionProof, validator_store::Error<Self::Error>> {
        unimplemented!()
    }

    async fn produce_sync_selection_proof(
        &self,
        _validator_pubkey: &PublicKeyBytes,
        _slot: Slot,
        _subnet_id: types::SyncSubnetId,
    ) -> Result<types::SyncSelectionProof, validator_store::Error<Self::Error>> {
        unimplemented!()
    }

    fn sign_aggregate_and_proofs(
        self: &Arc<Self>,
        _aggregates: Vec<AggregateToSign<Self::E>>,
    ) -> impl Stream<
        Item = Result<
            Vec<types::SignedAggregateAndProof<Self::E>>,
            validator_store::Error<Self::Error>,
        >,
    > + Send {
        futures::stream::empty()
    }

    fn sign_sync_committee_signatures(
        self: &Arc<Self>,
        _messages: Vec<SyncMessageToSign>,
    ) -> impl Stream<
        Item = Result<Vec<types::SyncCommitteeMessage>, validator_store::Error<Self::Error>>,
    > + Send {
        futures::stream::empty()
    }

    fn sign_sync_committee_contributions(
        self: &Arc<Self>,
        _contributions: Vec<ContributionToSign<Self::E>>,
    ) -> impl Stream<
        Item = Result<
            Vec<types::SignedContributionAndProof<Self::E>>,
            validator_store::Error<Self::Error>,
        >,
    > + Send {
        futures::stream::empty()
    }

    fn prune_slashing_protection_db(&self, _current_epoch: Epoch, _first_run: bool) {}

    async fn sign_execution_payload_envelope(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _envelope: types::ExecutionPayloadEnvelope<Self::E>,
    ) -> Result<
        types::SignedExecutionPayloadEnvelope<Self::E>,
        validator_store::Error<Self::Error>,
    > {
        unimplemented!()
    }

    async fn sign_payload_attestation(
        &self,
        _validator_pubkey: PublicKeyBytes,
        data: PayloadAttestationData,
    ) -> Result<PayloadAttestationMessage, validator_store::Error<Self::Error>> {
        Ok(PayloadAttestationMessage {
            validator_index: self.validator_index,
            data,
            signature: self.keypair.sk.sign(Hash256::repeat_byte(1)),
        })
    }

    async fn sign_proposer_preferences(
        &self,
        _validator_pubkey: PublicKeyBytes,
        _preferences: types::ProposerPreferences,
    ) -> Result<types::SignedProposerPreferences, validator_store::Error<Self::Error>> {
        unimplemented!()
    }

    fn proposal_data(&self, _pubkey: &PublicKeyBytes) -> Option<ProposalData> {
        None
    }
}
