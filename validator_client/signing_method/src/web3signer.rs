//! Contains the types required to make JSON requests to Web3Signer servers.

use super::Error;
use bls::{PublicKeyBytes, Signature};
use builder_types::RequestAuth;
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
    ExecutionPayloadEnvelope,
    PayloadAttestationMessage,
    ProposerPreferences,
    BuilderRequestAuth,
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
    Fulu,
    Gloas,
    Heze,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct ForkInfo {
    pub fork: Fork,
    pub genesis_validators_root: Hash256,
}

/// `{version, data}` wrapper for Gloas remote-signing payloads.
#[doc(hidden)]
#[derive(Debug, PartialEq, Serialize)]
pub struct VersionedForkData<'a, T> {
    version: ForkName,
    data: &'a T,
}

impl<'a, T> VersionedForkData<'a, T> {
    fn gloas(data: &'a T) -> Self {
        Self {
            version: ForkName::Gloas,
            data,
        }
    }
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
    ExecutionPayloadEnvelope(VersionedForkData<'a, ExecutionPayloadEnvelope<E>>),
    PayloadAttestationMessage(VersionedForkData<'a, PayloadAttestationData>),
    ProposerPreferences(VersionedForkData<'a, ProposerPreferences>),
    BuilderRequestAuth(VersionedForkData<'a, RequestAuth>),
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
            BeaconBlock::Fulu(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::Fulu,
                block: None,
                block_header: Some(block.block_header()),
            }),
            BeaconBlock::Gloas(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::Gloas,
                block: None,
                block_header: Some(block.block_header()),
            }),
            BeaconBlock::Heze(_) => Ok(Web3SignerObject::BeaconBlock {
                version: ForkName::Heze,
                block: None,
                block_header: Some(block.block_header()),
            }),
        }
    }

    pub fn execution_payload_envelope(envelope: &'a ExecutionPayloadEnvelope<E>) -> Self {
        Web3SignerObject::ExecutionPayloadEnvelope(VersionedForkData::gloas(envelope))
    }

    pub fn payload_attestation_message(data: &'a PayloadAttestationData) -> Self {
        Web3SignerObject::PayloadAttestationMessage(VersionedForkData::gloas(data))
    }

    pub fn proposer_preferences(preferences: &'a ProposerPreferences) -> Self {
        Web3SignerObject::ProposerPreferences(VersionedForkData::gloas(preferences))
    }

    pub fn builder_request_auth(request_auth: &'a RequestAuth) -> Self {
        Web3SignerObject::BuilderRequestAuth(VersionedForkData::gloas(request_auth))
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
            Web3SignerObject::ExecutionPayloadEnvelope(_) => MessageType::ExecutionPayloadEnvelope,
            Web3SignerObject::PayloadAttestationMessage(_) => {
                MessageType::PayloadAttestationMessage
            }
            Web3SignerObject::ProposerPreferences(_) => MessageType::ProposerPreferences,
            Web3SignerObject::BuilderRequestAuth(_) => MessageType::BuilderRequestAuth,
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

#[cfg(test)]
mod tests {
    use super::*;
    use bls::FixedBytesExtended;
    use builder_types::RequestAuthData;
    use types::{FullPayload, MainnetEthSpec};

    type E = MainnetEthSpec;
    type Payload = FullPayload<E>;

    fn dummy_fork_info() -> ForkInfo {
        ForkInfo {
            fork: Fork {
                previous_version: [0; 4],
                current_version: [1; 4],
                epoch: Epoch::new(1),
            },
            genesis_validators_root: Hash256::repeat_byte(42),
        }
    }

    fn serialize(
        message_type: MessageType,
        fork_info: Option<ForkInfo>,
        object: Web3SignerObject<'_, E, Payload>,
    ) -> serde_json::Value {
        serde_json::to_value(SigningRequest {
            message_type,
            fork_info,
            signing_root: Hash256::zero(),
            object,
        })
        .expect("signing request should serialize")
    }

    #[test]
    fn execution_payload_envelope_request_shape() {
        let envelope = ExecutionPayloadEnvelope::<E>::empty();
        let value = serialize(
            MessageType::ExecutionPayloadEnvelope,
            Some(dummy_fork_info()),
            Web3SignerObject::execution_payload_envelope(&envelope),
        );

        assert_eq!(value["type"], "EXECUTION_PAYLOAD_ENVELOPE");
        assert!(value.get("fork_info").is_some());
        assert_eq!(value["execution_payload_envelope"]["version"], "GLOAS");
        assert!(value["execution_payload_envelope"].get("data").is_some());
        assert!(value.get("payload_attestation_data").is_none());
        assert!(value.get("request_auth").is_none());
    }

    #[test]
    fn payload_attestation_message_request_shape() {
        let data = PayloadAttestationData {
            beacon_block_root: Hash256::zero(),
            slot: Slot::new(1),
            payload_present: true,
            blob_data_available: false,
        };
        let value = serialize(
            MessageType::PayloadAttestationMessage,
            Some(dummy_fork_info()),
            Web3SignerObject::payload_attestation_message(&data),
        );

        assert_eq!(value["type"], "PAYLOAD_ATTESTATION_MESSAGE");
        assert!(value.get("fork_info").is_some());
        assert_eq!(value["payload_attestation_message"]["version"], "GLOAS");
        assert_eq!(
            value["payload_attestation_message"]["data"]["payload_present"],
            true
        );
        assert!(value.get("payload_attestation_data").is_none());
        assert!(value.get("PAYLOAD_ATTESTATION").is_none());
    }

    #[test]
    fn proposer_preferences_request_shape() {
        let preferences = ProposerPreferences {
            dependent_root: Hash256::zero(),
            proposal_slot: Slot::new(32),
            validator_index: 1,
            fee_recipient: Address::repeat_byte(1),
            target_gas_limit: 30_000_000,
        };
        let value = serialize(
            MessageType::ProposerPreferences,
            Some(dummy_fork_info()),
            Web3SignerObject::proposer_preferences(&preferences),
        );

        assert_eq!(value["type"], "PROPOSER_PREFERENCES");
        assert!(value.get("fork_info").is_some());
        assert_eq!(value["proposer_preferences"]["version"], "GLOAS");
        assert_eq!(
            value["proposer_preferences"]["data"]["target_gas_limit"],
            "30000000"
        );
    }

    #[test]
    fn builder_request_auth_request_shape_omits_fork_info() {
        let request_auth = RequestAuth {
            data: RequestAuthData::new(b"http://builder.example.com".to_vec()).unwrap(),
            slot: Slot::new(32),
        };
        let value = serialize(
            MessageType::BuilderRequestAuth,
            None,
            Web3SignerObject::builder_request_auth(&request_auth),
        );

        assert_eq!(value["type"], "BUILDER_REQUEST_AUTH");
        assert!(value.get("fork_info").is_none());
        assert_eq!(value["builder_request_auth"]["version"], "GLOAS");
        assert!(value["builder_request_auth"]["data"].get("data").is_some());
        assert_eq!(value["builder_request_auth"]["data"]["slot"], "32");
        assert!(value.get("request_auth").is_none());
    }
}
