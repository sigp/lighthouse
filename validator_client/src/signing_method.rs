use eth2_keystore::Keystore;
use lockfile::Lockfile;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use types::{
    AggregateAndProof, AttestationData, BeaconBlock, ChainSpec, ContributionAndProof,
    DepositMessage, Domain, Epoch, EthSpec, Fork, Hash256, Keypair, PublicKey, PublicKeyBytes,
    Signature, SignedRoot, Slot, SyncAggregatorSelectionData, VoluntaryExit,
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
    pub fn get_signature<'a, T: EthSpec>(
        &self,
        domain: Domain,
        pre_image: PreImage<'a, T>,
        epoch: Epoch,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<Signature, Error> {
        let domain = spec.get_domain(epoch, domain, fork, genesis_validators_root);

        let signing_root = pre_image.signing_root(domain);

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

#[derive(Debug, PartialEq, Serialize)]
struct ForkInfo {
    fork: Fork,
    genesis_validators_root: Hash256,
}

#[derive(Debug, PartialEq, Serialize)]
pub enum PreImage<'a, T: EthSpec> {
    #[serde(rename = "aggregation_slot")]
    AggregationSlot { slot: Slot },
    #[serde(rename = "aggregate_and_proof")]
    AggregateAndProof(&'a AggregateAndProof<T>),
    #[serde(rename = "attestation")]
    AttestationData(&'a AttestationData),
    #[serde(rename = "block")]
    BeaconBlock(&'a BeaconBlock<T>),
    #[serde(rename = "deposit")]
    Deposit {
        pubkey: PublicKeyBytes,
        withdrawal_credentials: Hash256,
        #[serde(with = "serde_utils::quoted_u64")]
        amount: u64,
        #[serde(with = "serde_utils::bytes_4_hex")]
        genesis_fork_version: [u8; 4],
    },
    #[serde(rename = "randao_reveal")]
    RandaoReveal { epoch: Epoch },
    #[serde(rename = "voluntary_exit")]
    VoluntaryExit(&'a VoluntaryExit),
    #[serde(rename = "sync_committee_message")]
    SyncCommitteeMessage {
        beacon_block_root: Hash256,
        slot: Slot,
    },
    #[serde(rename = "sync_aggregator_selection_data")]
    SyncAggregatorSelectionData(&'a SyncAggregatorSelectionData),
    #[serde(rename = "contribution_and_proof")]
    ContributionAndProof(&'a ContributionAndProof<T>),
}

impl<'a, T: EthSpec> PreImage<'a, T> {
    fn message_type(&self) -> MessageType {
        match self {
            PreImage::AggregationSlot { .. } => MessageType::AggregationSlot,
            PreImage::AggregateAndProof(_) => MessageType::AggregateAndProof,
            PreImage::AttestationData(_) => MessageType::Attestation,
            PreImage::BeaconBlock(_) => MessageType::Block,
            PreImage::Deposit { .. } => MessageType::Deposit,
            PreImage::RandaoReveal { .. } => MessageType::RandaoReveal,
            PreImage::VoluntaryExit(_) => MessageType::VoluntaryExit,
            PreImage::SyncCommitteeMessage { .. } => MessageType::SyncCommitteeMessage,
            PreImage::SyncAggregatorSelectionData(_) => MessageType::SyncCommitteeSelectionProof,
            PreImage::ContributionAndProof(_) => MessageType::SyncCommitteeContributionAndProof,
        }
    }

    fn signing_root(&self, domain: Hash256) -> Hash256 {
        match self {
            PreImage::AggregationSlot { slot } => slot.signing_root(domain),
            PreImage::AggregateAndProof(a) => a.signing_root(domain),
            PreImage::AttestationData(a) => a.signing_root(domain),
            PreImage::BeaconBlock(b) => b.signing_root(domain),
            PreImage::Deposit {
                pubkey,
                withdrawal_credentials,
                amount,
                ..
            } => DepositMessage {
                pubkey: *pubkey,
                withdrawal_credentials: *withdrawal_credentials,
                amount: *amount,
            }
            .signing_root(domain),
            PreImage::RandaoReveal { epoch } => epoch.signing_root(domain),
            PreImage::VoluntaryExit(e) => e.signing_root(domain),
            PreImage::SyncCommitteeMessage {
                beacon_block_root, ..
            } => beacon_block_root.signing_root(domain),
            PreImage::SyncAggregatorSelectionData(s) => s.signing_root(domain),
            PreImage::ContributionAndProof(c) => c.signing_root(domain),
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
struct SigningRequest<'a, T: EthSpec> {
    #[serde(skip_serializing_if = "Option::is_none")]
    fork_info: Option<ForkInfo>,
    #[serde(rename = "signingRoot")]
    signing_root: Hash256,
    #[serde(flatten)]
    pre_image: PreImage<'a, T>,
}
