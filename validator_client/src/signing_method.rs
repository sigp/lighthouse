use eth2_keystore::Keystore;
use lockfile::Lockfile;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use task_executor::TaskExecutor;
use types::{
    AggregateAndProof, AttestationData, BeaconBlock, ChainSpec, ContributionAndProof,
    DepositMessage, Domain, Epoch, EthSpec, Fork, Hash256, Keypair, PublicKey, PublicKeyBytes,
    Signature, SignedRoot, Slot, SyncAggregatorSelectionData, VoluntaryExit,
};
use url::Url;

#[derive(Debug, PartialEq)]
pub enum Error {
    InconsistentDomains {
        message_type_domain: Domain,
        domain: Domain,
    },
    Web3SignerRequestFailed(String),
    Web3SignerJsonParsingFailed(String),
    ShuttingDown,
    TokioJoinError(String),
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
        voting_keypair: Arc<Keypair>,
    },
    /// A validator that defers to a HTTP server for signing.
    RemoteSigner {
        signing_url: Url,
        http_client: Client,
        voting_public_key: PublicKey,
    },
}

struct Signer<'a, T: EthSpec> {
    signing_method: Arc<SigningMethod>,
    domain: Domain,
    pre_image: PreImage<'a, T>,
    epoch: Epoch,
    fork: &'a Fork,
    genesis_validators_root: Hash256,
    spec: &'a ChainSpec,
    executor: &'a TaskExecutor,
}

/*
impl<'a, T: EthSpec> Signer<'a, T> {
    pub async fn sign(self) -> Result<Signature, Error> {
        // TODO(paul): should this be in a blocking task?
        let signing_root = self.pre_image.signing_root(self.spec.get_domain(
            self.epoch,
            self.domain,
            self.fork,
            self.genesis_validators_root,
        ));

        match self.signing_method.as_ref() {
            SigningMethod::LocalKeystore { voting_keypair, .. } => {
                let voting_keypair = voting_keypair.clone();
                let signature = self
                    .executor
                    .spawn_blocking_handle(
                        move || voting_keypair.sk.sign(signing_root),
                        "local_keystore_signer",
                    )
                    .ok_or(Error::ShuttingDown)?
                    .await
                    .map_err(|e| Error::TokioJoinError(e.to_string()))?;
                Ok(signature)
            }
            SigningMethod::RemoteSigner {
                signing_url,
                http_client,
                ..
            } => {
                let message_type = self.pre_image.message_type();

                // Sanity check.
                let message_type_domain = Domain::from(message_type);
                if message_type_domain != self.domain {
                    return Err(Error::InconsistentDomains {
                        message_type_domain,
                        domain: self.domain,
                    });
                }

                // The `fork_info` field is not required for deposits since they sign across the
                // genesis fork version.
                let fork_info = if let PreImage::Deposit { .. } = &self.pre_image {
                    None
                } else {
                    Some(ForkInfo {
                        fork: self.fork.clone(),
                        genesis_validators_root: self.genesis_validators_root,
                    })
                };

                let request = SigningRequest {
                    message_type,
                    fork_info,
                    signing_root,
                    pre_image: self.pre_image,
                };

                let response: SigningResponse = http_client
                    .post(signing_url.clone())
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::Web3SignerRequestFailed(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| Error::Web3SignerRequestFailed(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| Error::Web3SignerJsonParsingFailed(e.to_string()))?;

                Ok(response.signature)
            }
        }
    }
}
*/

impl SigningMethod {
    pub async fn get_signature<'a, T: EthSpec>(
        &self,
        domain: Domain,
        pre_image: PreImage<'a, T>,
        epoch: Epoch,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
        executor: &TaskExecutor,
    ) -> Result<Signature, Error> {
        // TODO(paul): should this be in a blocking task?
        let signing_root =
            pre_image.signing_root(spec.get_domain(epoch, domain, fork, genesis_validators_root));

        match self {
            SigningMethod::LocalKeystore { voting_keypair, .. } => {
                let voting_keypair = voting_keypair.clone();
                let signature = executor
                    .spawn_blocking_handle(
                        move || voting_keypair.sk.sign(signing_root),
                        "local_keystore_signer",
                    )
                    .ok_or(Error::ShuttingDown)?
                    .await
                    .map_err(|e| Error::TokioJoinError(e.to_string()))?;
                Ok(signature)
            }
            SigningMethod::RemoteSigner {
                signing_url,
                http_client,
                ..
            } => {
                let message_type = pre_image.message_type();

                // Sanity check.
                let message_type_domain = Domain::from(message_type);
                if message_type_domain != domain {
                    return Err(Error::InconsistentDomains {
                        message_type_domain,
                        domain,
                    });
                }

                // The `fork_info` field is not required for deposits since they sign across the
                // genesis fork version.
                let fork_info = if let PreImage::Deposit { .. } = &pre_image {
                    None
                } else {
                    Some(ForkInfo {
                        fork: fork.clone(),
                        genesis_validators_root,
                    })
                };

                let request = SigningRequest {
                    message_type,
                    fork_info,
                    signing_root,
                    pre_image,
                };

                let response: SigningResponse = http_client
                    .post(signing_url.clone())
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::Web3SignerRequestFailed(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| Error::Web3SignerRequestFailed(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| Error::Web3SignerJsonParsingFailed(e.to_string()))?;

                Ok(response.signature)
            }
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
#[serde(bound = "T: EthSpec")]
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
#[serde(bound = "T: EthSpec")]
struct SigningRequest<'a, T: EthSpec> {
    #[serde(rename = "type")]
    message_type: MessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    fork_info: Option<ForkInfo>,
    #[serde(rename = "signingRoot")]
    signing_root: Hash256,
    #[serde(flatten)]
    pre_image: PreImage<'a, T>,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SigningResponse {
    signature: Signature,
}
