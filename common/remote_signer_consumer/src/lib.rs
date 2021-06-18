//! Enables the [Lighthouse Ethereum 2.0 Client] to consume signatures from the
//! [BLS Remote Signer].
//!
//! ## About
//!
//! The lighthouse client needs to include this crate, and implement the
//! adequate bypasses and CLI flags needed to find the remote signer and perform
//! the HTTP requests.
//!
//! As defined by the [EIP-3030] specification, this crate will take the
//! received object data and parameters, and send them to the remote signer
//! for the production of a signing root hash and signature (the latter if the
//!  signer has in storage the key identified at request).
//!
//! ## Usage
//!
//! ### RemoteSignerHttpConsumer
//!
//! Just provide an `Url` and a timeout
//!
//! ```
//! use remote_signer_consumer::RemoteSignerHttpConsumer;
//! use reqwest::ClientBuilder;
//! use sensitive_url::SensitiveUrl;
//! use tokio::time::Duration;
//!
//! let url = SensitiveUrl::parse("http://127.0.0.1:9000").unwrap();
//! let reqwest_client = ClientBuilder::new()
//!       .timeout(Duration::from_secs(2))
//!       .build()
//!       .unwrap();
//!
//! let signer = RemoteSignerHttpConsumer::from_components(url, reqwest_client);
//!
//! ```
//!
//! ## sign API
//!
//! `POST /sign/:identifier`
//!
//! ### Arguments
//!
//! #### `public_key`
//!
//! Goes within the url to identify the key we want to use as signer.
//!
//! #### `bls_domain`
//!
//! [BLS Signature domain]. Supporting `BeaconProposer`, `BeaconAttester`,
//! `Randao`.
//!
//! #### `data`
//!
//! A `BeaconBlock`, `AttestationData`, or `Epoch`.
//!
//! #### `fork`
//!
//! A [`Fork`] object, containing previous and current versions.
//!
//! #### `genesis_validators_root`
//!
//! A [`Hash256`] for domain separation and chain versioning.
//!
//! ### Behavior
//!
//! Upon receiving and validating the parameters, the signer sends through the
//! wire a serialized `RemoteSignerRequestBody`. Receiving a `200` message with
//! the `signature` field inside a JSON payload, or an error.
//!
//! ## How it works
//!
//! The production of a _local_ signature (i.e. inside the Lighthouse client)
//! has slight variations among the kind of objects (block, attestation,
//! randao).
//!
//! To sign a message, the following procedures are needed:
//!
//! * Get the `fork_version` - From the objects `Fork` and `Epoch`.
//! * Compute the [`fork_data_root`] - From the `fork_version` and the
//!   `genesis_validators_root`.
//! * Compute the [`domain`] - From the `fork_data_root` and the `bls_domain`.
//! * With the `domain`, the object (or `epoch` in the case of [`randao`])
//!   can be merkelized into its [`signing_root`] to be signed.
//!
//! In short, to obtain a signature from the remote signer, we need to produce
//! (and serialize) the following objects:
//!
//! * `bls_domain`.
//! * `data` of the object, if this is a block proposal, an attestation, or an epoch.
//!   * `epoch`, obtained from the object.
//! * `fork`.
//! * `genesis_validators_root`.
//!
//! And, of course, the identifier of the secret key, the `public_key`.
//!
//! ## Future Work
//!
//! ### EIP-3030
//!
//! Work is being done to [standardize the API of the remote signers].
//!
//! [`domain`]: https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#compute_domain
//! [`Epoch`]: https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#custom-types
//! [`fork_data_root`]: https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#compute_fork_data_root
//! [`Fork`]: https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#fork
//! [`Hash256`]: https://docs.rs/ethereum-types/0.9.2/ethereum_types/struct.H256.html
//! [`randao`]: https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#randao
//! [`signing_root`]: https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#compute_signing_root
//! [BLS Remote Signer]: https://github.com/sigp/rust-bls-remote-signer
//! [BLS Signature domain]: https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#domain-types
//! [EIP-3030]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3030.md
//! [Lighthouse Ethereum 2.0 Client]: https://github.com/sigp/lighthouse
//! [standardize the API of the remote signers]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-3030.md

mod http_client;

pub use http_client::RemoteSignerHttpConsumer;
pub use reqwest::Url;
use sensitive_url::SensitiveUrl;
use serde::{Deserialize, Serialize};
use types::{AttestationData, BeaconBlock, Domain, Epoch, EthSpec, Fork, Hash256, SignedRoot};

#[derive(Debug)]
pub enum Error {
    /// The `reqwest` client raised an error.
    Reqwest(reqwest::Error),
    /// The server returned an error message where the body was able to be parsed.
    ServerMessage(String),
    /// The supplied URL is badly formatted. It should look something like `http://127.0.0.1:5052`.
    InvalidUrl(SensitiveUrl),
    /// The supplied parameter is invalid.
    InvalidParameter(String),
}

#[derive(Serialize)]
struct RemoteSignerRequestBody<T> {
    /// BLS Signature domain. Supporting `BeaconProposer`, `BeaconAttester`,`Randao`.
    bls_domain: String,

    /// A `BeaconBlock`, `AttestationData`, or `Epoch`.
    data: T,

    /// A `Fork` object containing previous and current versions.
    fork: Fork,

    /// A `Hash256` for domain separation and chain versioning.
    genesis_validators_root: Hash256,
}

#[derive(Deserialize)]
struct RemoteSignerResponseBodyOK {
    signature: String,
}

#[derive(Deserialize)]
struct RemoteSignerResponseBodyError {
    error: String,
}

/// Allows the verification of the BeaconBlock and AttestationData objects
/// to be sent through the wire, against their BLS Domains.
pub trait RemoteSignerObject: SignedRoot + Serialize {
    fn validate_object(&self, domain: Domain) -> Result<String, Error>;
    fn get_epoch(&self) -> Epoch;
}

impl<E: EthSpec> RemoteSignerObject for BeaconBlock<E> {
    fn validate_object(&self, domain: Domain) -> Result<String, Error> {
        match domain {
            Domain::BeaconProposer => Ok("beacon_proposer".to_string()),
            _ => Err(Error::InvalidParameter(format!(
                "Domain mismatch for the BeaconBlock object. Expected BeaconProposer, got {:?}",
                domain
            ))),
        }
    }

    fn get_epoch(&self) -> Epoch {
        self.epoch()
    }
}

impl RemoteSignerObject for AttestationData {
    fn validate_object(&self, domain: Domain) -> Result<String, Error> {
        match domain {
            Domain::BeaconAttester => Ok("beacon_attester".to_string()),
            _ => Err(Error::InvalidParameter(format!(
                "Domain mismatch for the AttestationData object. Expected BeaconAttester, got {:?}",
                domain
            ))),
        }
    }

    fn get_epoch(&self) -> Epoch {
        self.target.epoch
    }
}

impl RemoteSignerObject for Epoch {
    fn validate_object(&self, domain: Domain) -> Result<String, Error> {
        match domain {
            Domain::Randao => Ok("randao".to_string()),
            _ => Err(Error::InvalidParameter(format!(
                "Domain mismatch for the Epoch object. Expected Randao, got {:?}",
                domain
            ))),
        }
    }

    fn get_epoch(&self) -> Epoch {
        *self
    }
}
