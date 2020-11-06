use crate::api_error::ApiError;
use serde::Deserialize;
use serde_json::{from_value, Value};

use types::{
    AttestationData, BeaconBlock, ChainSpec, Domain, Epoch, EthSpec, Fork, Hash256, SignedRoot,
};

#[derive(Deserialize)]
pub struct SignMessageRequestBody {
    /// BLS Signature domain.
    /// Supporting `beacon_proposer`, `beacon_attester`, and `randao`.
    /// As defined in
    /// * https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#domain-types
    ///  * in lowercase, omitting the `domain` prefix.
    bls_domain: String,

    /// Supporting `block`, `attestation`, and `epoch`.
    /// (In LH these are `BeaconBlock`, `AttestationData`, and `Epoch`).
    /// As defined in
    /// * https://github.com/ethereum/eth2.0-APIs/blob/master/types/block.yaml
    /// * https://github.com/ethereum/eth2.0-APIs/blob/master/types/attestation.yaml
    /// * https://github.com/ethereum/eth2.0-APIs/blob/master/types/misc.yaml
    data: Value,

    /// A `Fork` object containing previous and current versions.
    /// As defined in
    /// * https://github.com/ethereum/eth2.0-APIs/blob/master/types/misc.yaml
    fork: Fork,

    /// A `Hash256` for domain separation and chain versioning.
    genesis_validators_root: Hash256,
}

pub fn get_signing_root<E: EthSpec>(
    req: &hyper::Request<std::vec::Vec<u8>>,
    spec: ChainSpec,
) -> Result<Hash256, ApiError> {
    let body: SignMessageRequestBody = serde_json::from_slice(req.body()).map_err(|e| {
        ApiError::BadRequest(format!("Unable to parse body message from JSON: {:?}", e))
    })?;

    let get_domain = |epoch, bls_domain| {
        spec.get_domain(epoch, bls_domain, &body.fork, body.genesis_validators_root)
    };

    match body.bls_domain.as_str() {
        "beacon_proposer" => {
            let block = from_value::<BeaconBlock<E>>(body.data.clone()).map_err(|e| {
                ApiError::BadRequest(format!("Unable to parse block from JSON: {:?}", e))
            })?;

            Ok(block.signing_root(get_domain(block.epoch(), Domain::BeaconProposer)))
        }

        "beacon_attester" => {
            let attestation = from_value::<AttestationData>(body.data.clone()).map_err(|e| {
                ApiError::BadRequest(format!("Unable to parse attestation from JSON: {:?}", e))
            })?;

            Ok(attestation
                .signing_root(get_domain(attestation.target.epoch, Domain::BeaconAttester)))
        }

        "randao" => {
            let epoch = from_value::<Epoch>(body.data.clone()).map_err(|e| {
                ApiError::BadRequest(format!("Unable to parse attestation from JSON: {:?}", e))
            })?;

            Ok(epoch.signing_root(get_domain(epoch, Domain::Randao)))
        }

        s => Err(ApiError::BadRequest(format!(
            "Unsupported bls_domain parameter: {}",
            s
        ))),
    }
}
