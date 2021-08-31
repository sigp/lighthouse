use serde::{Deserialize, Serialize};
use types::*;

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
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
pub struct ForkInfo {
    pub fork: Fork,
    pub genesis_validators_root: Hash256,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(bound = "T: EthSpec")]
pub enum PreImage<'a, T: EthSpec> {
    #[serde(rename = "aggregation_slot")]
    AggregationSlot { slot: Slot },
    #[serde(rename = "aggregate_and_proof")]
    AggregateAndProof(&'a AggregateAndProof<T>),
    #[serde(rename = "attestation")]
    AttestationData(&'a AttestationData),
    #[serde(rename = "block")]
    BeaconBlockBase(&'a BeaconBlockBase<T>),
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
    pub fn beacon_block(block: &'a BeaconBlock<T>) -> Self {
        match block {
            BeaconBlock::Base(b) => PreImage::BeaconBlockBase(b),
            // TODO(paul): implement as per https://github.com/ConsenSys/web3signer/pull/422
            BeaconBlock::Altair(_) => unimplemented!("altair block"),
        }
    }
}

impl<'a, T: EthSpec> PreImage<'a, T> {
    pub fn message_type(&self) -> MessageType {
        match self {
            PreImage::AggregationSlot { .. } => MessageType::AggregationSlot,
            PreImage::AggregateAndProof(_) => MessageType::AggregateAndProof,
            PreImage::AttestationData(_) => MessageType::Attestation,
            PreImage::BeaconBlockBase(_) => MessageType::Block,
            PreImage::Deposit { .. } => MessageType::Deposit,
            PreImage::RandaoReveal { .. } => MessageType::RandaoReveal,
            PreImage::VoluntaryExit(_) => MessageType::VoluntaryExit,
            PreImage::SyncCommitteeMessage { .. } => MessageType::SyncCommitteeMessage,
            PreImage::SyncAggregatorSelectionData(_) => MessageType::SyncCommitteeSelectionProof,
            PreImage::ContributionAndProof(_) => MessageType::SyncCommitteeContributionAndProof,
        }
    }

    pub fn signing_root(&self, domain: Hash256) -> Hash256 {
        match self {
            PreImage::AggregationSlot { slot } => slot.signing_root(domain),
            PreImage::AggregateAndProof(a) => a.signing_root(domain),
            PreImage::AttestationData(a) => a.signing_root(domain),
            PreImage::BeaconBlockBase(b) => BeaconBlockRef::Base(b).signing_root(domain),
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
#[serde(bound = "T: EthSpec")]
pub struct SigningRequest<'a, T: EthSpec> {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork_info: Option<ForkInfo>,
    #[serde(rename = "signingRoot")]
    pub signing_root: Hash256,
    #[serde(flatten)]
    pub pre_image: PreImage<'a, T>,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct SigningResponse {
    pub signature: Signature,
}
