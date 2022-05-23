use crate::{EthSpec, ExecPayload, Uint256};
use bls::blst_implementations::PublicKeyBytes;
use bls::Signature;
use serde_derive::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "E: EthSpec, Payload: ExecPayload<E>")]
pub struct BuilderBid<E: EthSpec, Payload: ExecPayload<E>> {
    pub header: Payload,
    pub value: Uint256,
    pub pubkey: PublicKeyBytes,
    _phantom_data: PhantomData<E>,
}

/// Validator registration, for use in interacting with servers implementing the builder API.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "E: EthSpec, Payload: ExecPayload<E>")]
pub struct SignedBuilderBid<E: EthSpec, Payload: ExecPayload<E>> {
    pub message: BuilderBid<E, Payload>,
    pub signature: Signature,
}
