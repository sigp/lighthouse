//! Provides methods for obtaining validator signatures, including:
//!
//! - Via a local `Keypair`.
//! - Via a remote signer (Web3Signer)

use crate::http_metrics::metrics;
use eth2_keystore::Keystore;
use lockfile::Lockfile;
use parking_lot::{Mutex, RwLock};
use reqwest::Client;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use task_executor::TaskExecutor;
use types::*;
use url::Url;
use web3signer::{ForkInfo, SigningRequest, SigningResponse};

pub use web3signer::Web3SignerObject;

mod web3signer;

const MAX_SIGNATURE_CACHE_SIZE: usize = 64;

#[derive(Debug, PartialEq)]
pub enum Error {
    InconsistentDomains {
        message_type_domain: Domain,
        domain: Domain,
    },
    Web3SignerRequestFailed(String),
    Web3SignerJsonParsingFailed(String),
    ShuttingDown,
    TokioJoin(String),
    MergeForkNotSupported,
}

/// Enumerates all messages that can be signed by a validator.
#[derive(Debug)]
pub enum SignableMessage<'a, T: EthSpec, Payload: ExecPayload<T> = FullPayload<T>> {
    RandaoReveal(Epoch),
    BeaconBlock(&'a BeaconBlock<T, Payload>),
    AttestationData(&'a AttestationData),
    SignedAggregateAndProof(&'a AggregateAndProof<T>),
    SelectionProof(Slot),
    SyncSelectionProof(&'a SyncAggregatorSelectionData),
    SyncCommitteeSignature {
        beacon_block_root: Hash256,
        slot: Slot,
    },
    SignedContributionAndProof(&'a ContributionAndProof<T>),
}

impl<'a, T: EthSpec, Payload: ExecPayload<T>> SignableMessage<'a, T, Payload> {
    /// Returns the `SignedRoot` for the contained message.
    ///
    /// The actual `SignedRoot` trait is not used since it also requires a `TreeHash` impl, which is
    /// not required here.
    pub fn signing_root(&self, domain: Hash256) -> Hash256 {
        match self {
            SignableMessage::RandaoReveal(epoch) => epoch.signing_root(domain),
            SignableMessage::BeaconBlock(b) => b.signing_root(domain),
            SignableMessage::AttestationData(a) => a.signing_root(domain),
            SignableMessage::SignedAggregateAndProof(a) => a.signing_root(domain),
            SignableMessage::SelectionProof(slot) => slot.signing_root(domain),
            SignableMessage::SyncSelectionProof(s) => s.signing_root(domain),
            SignableMessage::SyncCommitteeSignature {
                beacon_block_root, ..
            } => beacon_block_root.signing_root(domain),
            SignableMessage::SignedContributionAndProof(c) => c.signing_root(domain),
        }
    }
}

/// A method used by a validator to sign messages.
///
/// Presently there is only a single variant, however we expect more variants to arise (e.g.,
/// remote signing).
pub enum SigningMethod {
    /// A validator that is defined by an EIP-2335 keystore on the local filesystem.
    LocalKeystore {
        voting_keystore_path: PathBuf,
        voting_keystore_lockfile: Mutex<Option<Lockfile>>,
        voting_keystore: Keystore,
        voting_keypair: Arc<Keypair>,
    },
    /// A validator that defers to a Web3Signer server for signing.
    ///
    /// See: https://docs.web3signer.consensys.net/en/latest/
    Web3Signer {
        signing_url: Url,
        http_client: Client,
        voting_public_key: PublicKey,
    },
}

/// A cache for signatures previously used for different verifications and proofs.
/// Currently, caching is only used for Selection Proof message variants.
pub type SignatureCache = HashMap<Hash256, (Signature, Slot)>;

/// Handler type to manage signing methods and caches on a per-validator basis.
pub struct SigningHandler {
    pub method: SigningMethod,
    pub selection_proof_signature_cache: RwLock<SignatureCache>,
    pub sync_selection_proof_signature_cache: RwLock<SignatureCache>,
}

impl SigningHandler {
    pub fn new(method: SigningMethod) -> Self {
        Self {
            method,
            selection_proof_signature_cache: RwLock::new(HashMap::with_capacity(
                MAX_SIGNATURE_CACHE_SIZE,
            )),
            sync_selection_proof_signature_cache: RwLock::new(HashMap::with_capacity(
                MAX_SIGNATURE_CACHE_SIZE,
            )),
        }
    }
}

/// The additional information used to construct a signature. Mostly used for protection from replay
/// attacks.
pub struct SigningContext {
    pub domain: Domain,
    pub epoch: Epoch,
    pub fork: Fork,
    pub genesis_validators_root: Hash256,
}

impl SigningContext {
    /// Returns the `Hash256` to be mixed-in with the signature.
    pub fn domain_hash(&self, spec: &ChainSpec) -> Hash256 {
        spec.get_domain(
            self.epoch,
            self.domain,
            &self.fork,
            self.genesis_validators_root,
        )
    }
}

impl SigningHandler {
    fn get_from_cache<T: EthSpec, Payload: ExecPayload<T>>(
        &self,
        signing_root: &Hash256,
        message_type: &SignableMessage<'_, T, Payload>,
    ) -> Option<Signature> {
        match message_type {
            SignableMessage::SelectionProof(_) => self
                .selection_proof_signature_cache
                .read()
                .get(signing_root)
                .map(|val| val.0.clone()),
            SignableMessage::SyncSelectionProof(_) => self
                .sync_selection_proof_signature_cache
                .read()
                .get(signing_root)
                .map(|val| val.0.clone()),
            _ => None,
        }
    }

    fn store_in_cache<T: EthSpec, Payload: ExecPayload<T>>(
        &self,
        signing_root: Hash256,
        signature: Signature,
        message: &SignableMessage<'_, T, Payload>,
    ) {
        match message {
            SignableMessage::SelectionProof(slot) => {
                let mut cache = self.selection_proof_signature_cache.write();
                if cache.len() >= MAX_SIGNATURE_CACHE_SIZE {
                    // Find the entry with the oldest slot and prune it.
                    let min_slot = cache.iter().min_by_key(|(_, (_, slot))| slot);
                    if let Some(item) = min_slot {
                        let min_key = *item.0;
                        cache.remove(&min_key);
                    }
                }
                cache.insert(signing_root, (signature, *slot));
            }
            SignableMessage::SyncSelectionProof(data) => {
                let mut cache = self.sync_selection_proof_signature_cache.write();
                if cache.len() >= MAX_SIGNATURE_CACHE_SIZE {
                    // Find the entry with the oldest slot and prune it.
                    let min_slot = cache.iter().min_by_key(|(_, (_, slot))| slot);
                    if let Some(item) = min_slot {
                        let min_key = *item.0;
                        cache.remove(&min_key);
                    }
                }
                cache.insert(signing_root, (signature, data.slot));
            }
            _ => (),
        }
    }

    /// Return the signature of `signable_message`, with respect to the `signing_context`.
    pub async fn get_signature<T: EthSpec, Payload: ExecPayload<T>>(
        &self,
        signable_message: SignableMessage<'_, T, Payload>,
        signing_context: SigningContext,
        spec: &ChainSpec,
        executor: &TaskExecutor,
    ) -> Result<Signature, Error> {
        let domain_hash = signing_context.domain_hash(spec);
        let SigningContext {
            fork,
            genesis_validators_root,
            ..
        } = signing_context;

        let signing_root = signable_message.signing_root(domain_hash);

        // Use cached signature if it exists.
        let cached = match signable_message {
            SignableMessage::SelectionProof(_) => {
                self.get_from_cache(&signing_root, &signable_message)
            }
            SignableMessage::SyncSelectionProof(_) => {
                self.get_from_cache(&signing_root, &signable_message)
            }
            _ => None,
        };

        match &self.method {
            SigningMethod::LocalKeystore { voting_keypair, .. } => {
                match cached {
                    Some(signature) => {
                        metrics::inc_counter_vec(
                            &metrics::SIGNATURE_CACHE_HIT,
                            &[metrics::LOCAL_KEYSTORE],
                        );
                        return Ok(signature);
                    }
                    None => (),
                };

                let timer =
                    metrics::start_timer_vec(&metrics::SIGNING_TIMES, &[metrics::LOCAL_KEYSTORE]);

                let voting_keypair = voting_keypair.clone();
                // Spawn a blocking task to produce the signature. This avoids blocking the core
                // tokio executor.
                let signature = executor
                    .spawn_blocking_handle(
                        move || voting_keypair.sk.sign(signing_root),
                        "local_keystore_signer",
                    )
                    .ok_or(Error::ShuttingDown)?
                    .await
                    .map_err(|e| Error::TokioJoin(e.to_string()))?;
                drop(timer);

                match signable_message {
                    // Store signatures for selection proof messages in the signature cache.
                    SignableMessage::SelectionProof(_) => {
                        self.store_in_cache(signing_root, signature.clone(), &signable_message)
                    }
                    SignableMessage::SyncSelectionProof(_) => {
                        self.store_in_cache(signing_root, signature.clone(), &signable_message)
                    }
                    _ => (),
                };

                Ok(signature)
            }
            SigningMethod::Web3Signer {
                signing_url,
                http_client,
                ..
            } => {
                match cached {
                    Some(signature) => {
                        metrics::inc_counter_vec(
                            &metrics::SIGNATURE_CACHE_HIT,
                            &[metrics::WEB3SIGNER],
                        );
                        return Ok(signature);
                    }
                    None => (),
                };

                let timer =
                    metrics::start_timer_vec(&metrics::SIGNING_TIMES, &[metrics::WEB3SIGNER]);

                // Map the message into a Web3Signer type.
                let object = match signable_message {
                    SignableMessage::RandaoReveal(epoch) => {
                        Web3SignerObject::RandaoReveal { epoch }
                    }
                    SignableMessage::BeaconBlock(block) => Web3SignerObject::beacon_block(block)?,
                    SignableMessage::AttestationData(a) => Web3SignerObject::Attestation(a),
                    SignableMessage::SignedAggregateAndProof(a) => {
                        Web3SignerObject::AggregateAndProof(a)
                    }
                    SignableMessage::SelectionProof(slot) => {
                        Web3SignerObject::AggregationSlot { slot }
                    }
                    SignableMessage::SyncSelectionProof(s) => {
                        Web3SignerObject::SyncAggregatorSelectionData(s)
                    }
                    SignableMessage::SyncCommitteeSignature {
                        beacon_block_root,
                        slot,
                    } => Web3SignerObject::SyncCommitteeMessage {
                        beacon_block_root,
                        slot,
                    },
                    SignableMessage::SignedContributionAndProof(c) => {
                        Web3SignerObject::ContributionAndProof(c)
                    }
                };

                // Determine the Web3Signer message type.
                let message_type = object.message_type();

                // The `fork_info` field is not required for deposits since they sign across the
                // genesis fork version.
                let fork_info = if let Web3SignerObject::Deposit { .. } = &object {
                    None
                } else {
                    Some(ForkInfo {
                        fork,
                        genesis_validators_root,
                    })
                };

                let request = SigningRequest {
                    message_type,
                    fork_info,
                    signing_root,
                    object,
                };

                // Request a signature from the Web3Signer instance via HTTP(S).
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
                drop(timer);

                match signable_message {
                    // Store signature in the signature cache.
                    SignableMessage::SelectionProof(_) => self.store_in_cache(
                        signing_root,
                        response.signature.clone(),
                        &signable_message,
                    ),
                    SignableMessage::SyncSelectionProof(_) => self.store_in_cache(
                        signing_root,
                        response.signature.clone(),
                        &signable_message,
                    ),
                    _ => (),
                };

                Ok(response.signature)
            }
        }
    }
}
