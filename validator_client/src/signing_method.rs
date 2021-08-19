use eth2_keystore::Keystore;
use lockfile::Lockfile;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use types::{
    AggregateAndProof, AttestationData, BeaconBlock, ChainSpec, ContributionAndProof, Deposit,
    Domain, Epoch, EthSpec, Fork, Hash256, Keypair, PublicKey, Signature, SignedRoot, Slot,
    SyncAggregatorSelectionData, VoluntaryExit,
};

#[derive(Debug, PartialEq)]
pub enum Error {
    Todo,
}

/// A method used by a validator to sign messages.
///
/// Presently there is only a single variant, however we expect more variants to arise (e.g.,
/// remote signing).
pub enum SigningMethod {
    /// A validator that is defined by an EIP-2335 keystore on the local filesystem.
    LocalKeystore {
        voting_keystore_path: PathBuf,
        voting_keystore_lockfile: Lockfile,
        voting_keystore: Keystore,
        voting_keypair: Keypair,
    },
    /// A validator that defers to a HTTP server for signing.
    RemoteSigner {
        url: Url,
        http_client: Client,
        voting_public_key: PublicKey,
    },
}

impl SigningMethod {
    pub fn get_signature<T: SignedRoot>(
        &self,
        domain: Domain,
        data: &T,
        epoch: Epoch,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<Signature, Error> {
        let domain = spec.get_domain(epoch, domain, fork, genesis_validators_root);

        let signing_root = data.signing_root(domain);

        match self {
            SigningMethod::LocalKeystore { voting_keypair, .. } => {
                Ok(voting_keypair.sk.sign(signing_root))
            }
            SigningMethod::RemoteSigner { .. } => todo!(),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType {
    AggregationSlot,
    AggregateAndProof,
    Attestation,
    Block,
    Deposit,
    RandaoReveal,
    VoluntaryExit,
    SyncCommitteeMessage,
    SyncCommitteeSelectionProof,
    SyncCommitteeContributionAndProof,
}

impl From<MessageType> for Domain {
    fn from(message_type: MessageType) -> Self {
        match message_type {
            MessageType::AggregationSlot => Domain::SelectionProof,
            MessageType::AggregateAndProof => Domain::AggregateAndProof,
            MessageType::Attestation => Domain::BeaconAttester,
            MessageType::Block => Domain::BeaconProposer,
            MessageType::Deposit => Domain::Deposit,
            MessageType::RandaoReveal => Domain::Randao,
            MessageType::VoluntaryExit => Domain::VoluntaryExit,
            MessageType::SyncCommitteeMessage => Domain::SyncCommittee,
            MessageType::SyncCommitteeSelectionProof => Domain::SyncCommitteeSelectionProof,
            MessageType::SyncCommitteeContributionAndProof => Domain::ContributionAndProof,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct ForkInfo {
    fork: Fork,
    genesis_validators_root: Hash256,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum PreImage<T: EthSpec> {
    #[serde(rename = "aggregation_slot")]
    AggregationSlot { slot: Slot },
    #[serde(rename = "aggregate_and_proof")]
    AggregateAndProof(AggregateAndProof<T>),
    #[serde(rename = "attestation")]
    AttestationData(AttestationData),
    #[serde(rename = "block")]
    BeaconBlock(BeaconBlock<T>),
    #[serde(rename = "deposit")]
    Deposit(Deposit),
    #[serde(rename = "randao_reveal")]
    RandaoReveal { epoch: Epoch },
    #[serde(rename = "voluntary_exit")]
    VoluntaryExit(VoluntaryExit),
    #[serde(rename = "sync_committee_message")]
    SyncCommitteeMessage {
        beacon_block_root: Hash256,
        slot: Slot,
    },
    #[serde(rename = "sync_aggregator_selection_data")]
    SyncAggregatorSelectionData(SyncAggregatorSelectionData),
    #[serde(rename = "contribution_and_proof")]
    ContributionAndProof(ContributionAndProof<T>),
}

impl<T: EthSpec> PreImage<T> {
    fn message_type(&self) -> MessageType {
        match self {
            PreImage::AggregationSlot { .. } => MessageType::AggregationSlot,
            PreImage::AggregateAndProof(_) => MessageType::AggregateAndProof,
            PreImage::AttestationData(_) => MessageType::Attestation,
            PreImage::BeaconBlock(_) => MessageType::Block,
            PreImage::Deposit(_) => MessageType::Deposit,
            PreImage::RandaoReveal { .. } => MessageType::RandaoReveal,
            PreImage::VoluntaryExit(_) => MessageType::VoluntaryExit,
            PreImage::SyncCommitteeMessage { .. } => MessageType::SyncCommitteeMessage,
            PreImage::SyncAggregatorSelectionData(_) => MessageType::SyncCommitteeSelectionProof,
            PreImage::ContributionAndProof(_) => MessageType::SyncCommitteeContributionAndProof,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct SigningRequest<T: EthSpec> {
    fork_info: ForkInfo,
    signing_root: Hash256,
    #[serde(flatten)]
    pre_image: PreImage<T>,
}
