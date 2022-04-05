//! Contains the types required to make JSON requests to Web3Signer servers.

use super::Error;
use serde::{Deserialize, Serialize};
use types::*;

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType {
    AggregationSlot,
    AggregateAndProof,
    Attestation,
    BlockV2,
    Deposit,
    RandaoReveal,
    VoluntaryExit,
    SyncCommitteeMessage,
    SyncCommitteeSelectionProof,
    SyncCommitteeContributionAndProof,
    ValidatorRegistration,
}

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ForkName {
    Phase0,
    Altair,
    Bellatrix,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ForkInfo {
    pub fork: Fork,
    pub genesis_validators_root: Hash256,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(bound = "T: EthSpec", rename_all = "snake_case")]
pub enum Web3SignerObject<'a, T: EthSpec, Payload: ExecPayload<T>> {
    AggregationSlot {
        slot: Slot,
    },
    AggregateAndProof(&'a AggregateAndProof<T>),
    Attestation(&'a AttestationData),
    BeaconBlock {
        version: ForkName,
        #[serde(skip_serializing_if = "Option::is_none")]
        block: Option<&'a BeaconBlock<T, Payload>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        block_header: Option<BeaconBlockHeader>,
    },
    #[allow(dead_code)]
    Deposit {
        pubkey: PublicKeyBytes,
        withdrawal_credentials: Hash256,
        #[serde(with = "eth2_serde_utils::quoted_u64")]
        amount: u64,
        #[serde(with = "eth2_serde_utils::bytes_4_hex")]
        genesis_fork_version: [u8; 4],
    },
    RandaoReveal {
        epoch: Epoch,
    },
    #[allow(dead_code)]
    VoluntaryExit(&'a VoluntaryExit),
    SyncCommitteeMessage {
        beacon_block_root: Hash256,
        slot: Slot,
    },
    SyncAggregatorSelectionData(&'a SyncAggregatorSelectionData),
    ContributionAndProof(&'a ContributionAndProof<T>),
    ValidatorRegistration(&'a ValidatorRegistrationData),
}

impl<'a, T: EthSpec, Payload: ExecPayload<T>> Web3SignerObject<'a, T, Payload> {
    pub fn beacon_block(block: &'a BeaconBlock<T, Payload>) -> Result<Self, Error> {
        match block {
            BeaconBlock::Base(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::Phase0,
                block: Some(block),
                block_header: None,
            }),
            BeaconBlock::Altair(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::Altair,
                block: Some(block),
                block_header: None,
            }),
            BeaconBlock::Merge(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::Bellatrix,
                block: None,
                block_header: Some(block.block_header()),
            }),
            BeaconBlock::Capella(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::Capella,
                block: None,
                block_header: Some(block.block_header()),
            }),
        }
    }

    pub fn message_type(&self) -> MessageType {
        match self {
            Web3SignerObject::AggregationSlot { .. } => MessageType::AggregationSlot,
            Web3SignerObject::AggregateAndProof(_) => MessageType::AggregateAndProof,
            Web3SignerObject::Attestation(_) => MessageType::Attestation,
            Web3SignerObject::BeaconBlock { .. } => MessageType::BlockV2,
            Web3SignerObject::Deposit { .. } => MessageType::Deposit,
            Web3SignerObject::RandaoReveal { .. } => MessageType::RandaoReveal,
            Web3SignerObject::VoluntaryExit(_) => MessageType::VoluntaryExit,
            Web3SignerObject::SyncCommitteeMessage { .. } => MessageType::SyncCommitteeMessage,
            Web3SignerObject::SyncAggregatorSelectionData(_) => {
                MessageType::SyncCommitteeSelectionProof
            }
            Web3SignerObject::ContributionAndProof(_) => {
                MessageType::SyncCommitteeContributionAndProof
            }
            Web3SignerObject::ValidatorRegistration(_) => MessageType::ValidatorRegistration,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(bound = "T: EthSpec")]
pub struct SigningRequest<'a, T: EthSpec, Payload: ExecPayload<T>> {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork_info: Option<ForkInfo>,
    #[serde(rename = "signingRoot")]
    pub signing_root: Hash256,
    #[serde(flatten)]
    pub object: Web3SignerObject<'a, T, Payload>,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct SigningResponse {
    pub signature: Signature,
}
