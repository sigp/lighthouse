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
    #[allow(dead_code)]
    Deposit {
        pubkey: PublicKeyBytes,
        withdrawal_credentials: Hash256,
        #[serde(with = "eth2_serde_utils::quoted_u64")]
        amount: u64,
        #[serde(with = "eth2_serde_utils::bytes_4_hex")]
        genesis_fork_version: [u8; 4],
    },
    #[serde(rename = "randao_reveal")]
    RandaoReveal { epoch: Epoch },
    #[serde(rename = "voluntary_exit")]
    #[allow(dead_code)]
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
