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
    Capella,
    Deneb,
    Electra,
    EIP7732,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ForkInfo {
    pub fork: Fork,
    pub genesis_validators_root: Hash256,
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(bound = "E: EthSpec", rename_all = "snake_case")]
pub enum Web3SignerObject<'a, E: EthSpec, Payload: AbstractExecPayload<E>> {
    AggregationSlot {
        slot: Slot,
    },
    AggregateAndProof(AggregateAndProofRef<'a, E>),
    Attestation(&'a AttestationData),
    BeaconBlock {
        version: ForkName,
        #[serde(skip_serializing_if = "Option::is_none")]
        block: Option<&'a BeaconBlock<E, Payload>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        block_header: Option<BeaconBlockHeader>,
    },
    #[allow(dead_code)]
    Deposit {
        pubkey: PublicKeyBytes,
        withdrawal_credentials: Hash256,
        #[serde(with = "serde_utils::quoted_u64")]
        amount: u64,
        #[serde(with = "serde_utils::bytes_4_hex")]
        genesis_fork_version: [u8; 4],
    },
    RandaoReveal {
        epoch: Epoch,
    },
    VoluntaryExit(&'a VoluntaryExit),
    SyncCommitteeMessage {
        beacon_block_root: Hash256,
        slot: Slot,
    },
    SyncAggregatorSelectionData(&'a SyncAggregatorSelectionData),
    ContributionAndProof(&'a ContributionAndProof<E>),
    ValidatorRegistration(&'a ValidatorRegistrationData),
}

impl<'a, E: EthSpec, Payload: AbstractExecPayload<E>> Web3SignerObject<'a, E, Payload> {
    pub fn beacon_block(block: &'a BeaconBlock<E, Payload>) -> Result<Self, Error> {
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
            BeaconBlock::Bellatrix(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::Bellatrix,
                block: None,
                block_header: Some(block.block_header()),
            }),
            BeaconBlock::Capella(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::Capella,
                block: None,
                block_header: Some(block.block_header()),
            }),
            BeaconBlock::Deneb(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::Deneb,
                block: None,
                block_header: Some(block.block_header()),
            }),
            BeaconBlock::Electra(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::Electra,
                block: None,
                block_header: Some(block.block_header()),
            }),
            BeaconBlock::EIP7732(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::EIP7732,
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
#[serde(bound = "E: EthSpec")]
pub struct SigningRequest<'a, E: EthSpec, Payload: AbstractExecPayload<E>> {
    #[serde(rename = "type")]
    pub message_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork_info: Option<ForkInfo>,
    #[serde(rename = "signingRoot")]
    pub signing_root: Hash256,
    #[serde(flatten)]
    pub object: Web3SignerObject<'a, E, Payload>,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct SigningResponse {
    pub signature: Signature,
}
