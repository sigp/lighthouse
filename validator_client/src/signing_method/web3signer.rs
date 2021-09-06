//! Contains the types required to make JSON requests to Web3Signer servers.

use serde::{Deserialize, Serialize};
use types::*;

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType {
    AggregationSlot,
    AggregateAndProof,
    Attestation,
    #[serde(rename = "BLOCK_V2")]
    BlockV2,
    Deposit,
    RandaoReveal,
    VoluntaryExit,
    SyncCommitteeMessage,
    SyncCommitteeSelectionProof,
    SyncCommitteeContributionAndProof,
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
pub enum ForkName {
    #[serde(rename = "PHASE0")]
    Phase0,
    #[serde(rename = "ALTAIR")]
    Altair,
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
    #[serde(rename = "beacon_block")]
    BeaconBlock {
        version: ForkName,
        block: &'a BeaconBlock<T>,
    },
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
    pub fn beacon_block(block: &'a BeaconBlock<T>) -> Self {
        let version = match block {
            BeaconBlock::Base(_) => ForkName::Phase0,
            BeaconBlock::Altair(_) => ForkName::Altair,
        };

        PreImage::BeaconBlock { version, block }
    }

    pub fn message_type(&self) -> MessageType {
        match self {
            PreImage::AggregationSlot { .. } => MessageType::AggregationSlot,
            PreImage::AggregateAndProof(_) => MessageType::AggregateAndProof,
            PreImage::AttestationData(_) => MessageType::Attestation,
            PreImage::BeaconBlock { .. } => MessageType::BlockV2,
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
