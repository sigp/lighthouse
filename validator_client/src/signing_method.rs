use eth2_keystore::Keystore;
use lockfile::Lockfile;
use reqwest::{Client, Url};
use std::path::PathBuf;
use types::{ChainSpec, Domain, Epoch, Fork, Hash256, Keypair, PublicKey, Signature, SignedRoot};

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
    pub fn get_signature<T: SignedRoot>(
        &self,
        domain: Domain,
        data: &T,
        epoch: Epoch,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<Signature, Error> {
        let domain = spec.get_domain(epoch, domain, fork, genesis_validators_root);

        let signing_root = data.signing_root(domain);

        match self {
            SigningMethod::LocalKeystore { voting_keypair, .. } => {
                Ok(voting_keypair.sk.sign(signing_root))
            }
            SigningMethod::RemoteSigner { .. } => todo!(),
        }
    }
}
