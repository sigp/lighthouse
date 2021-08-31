use eth2_keystore::Keystore;
use lockfile::Lockfile;
use reqwest::Client;
use std::path::PathBuf;
use std::sync::Arc;
use task_executor::TaskExecutor;
use types::{ChainSpec, Domain, Epoch, EthSpec, Fork, Hash256, Keypair, PublicKey, Signature};
use url::Url;
use web3signer::{ForkInfo, SigningRequest, SigningResponse};

pub use web3signer::PreImage;

mod web3signer;

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
    /// A validator that defers to a Web3Signer server for signing.
    ///
    /// See: https://docs.web3signer.consensys.net/en/latest/
    Web3Signer {
        signing_url: Url,
        http_client: Client,
        voting_public_key: PublicKey,
    },
}

pub struct SigningContext {
    pub domain: Domain,
    pub epoch: Epoch,
    pub fork: Fork,
    pub genesis_validators_root: Hash256,
}

impl SigningContext {
    pub fn domain_hash(&self, spec: &ChainSpec) -> Hash256 {
        spec.get_domain(
            self.epoch,
            self.domain,
            &self.fork,
            self.genesis_validators_root,
        )
    }
}

impl SigningMethod {
    pub async fn get_signature<T: EthSpec>(
        &self,
        pre_image: PreImage<'_, T>,
        signing_context: SigningContext,
        spec: &ChainSpec,
        executor: &TaskExecutor,
    ) -> Result<Signature, Error> {
        let domain_hash = signing_context.domain_hash(spec);
        let SigningContext {
            domain,
            epoch: _,
            fork,
            genesis_validators_root,
        } = signing_context;

        // TODO(paul): should this be in a blocking task?
        let signing_root = pre_image.signing_root(domain_hash);

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
                    .map_err(|e| Error::TokioJoin(e.to_string()))?;
                Ok(signature)
            }
            SigningMethod::Web3Signer {
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
                        fork,
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
