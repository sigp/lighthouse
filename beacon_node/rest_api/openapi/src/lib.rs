#![allow(missing_docs, trivial_casts, unused_variables, unused_mut, unused_imports, unused_extern_crates, non_camel_case_types)]
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;


extern crate futures;
extern crate chrono;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

// Logically this should be in the client and server modules, but rust doesn't allow `macro_use` from a module.
#[cfg(any(feature = "client", feature = "server"))]
#[macro_use]
extern crate hyper;

extern crate swagger;

#[macro_use]
extern crate url;

use futures::Stream;
use std::io::Error;

#[allow(unused_imports)]
use std::collections::HashMap;

pub use futures::Future;

#[cfg(any(feature = "client", feature = "server"))]
mod mimetypes;

pub use swagger::{ApiError, ContextWrapper};

pub const BASE_PATH: &'static str = "";
pub const API_VERSION: &'static str = "0.2.0";


#[derive(Debug, PartialEq)]
pub enum NodeGenesisTimeGetResponse {
    /// Request successful
    RequestSuccessful ( i32 ) ,
    /// Beacon node internal error.
    BeaconNodeInternalError ,
}

#[derive(Debug, PartialEq)]
pub enum NodeSyncingGetResponse {
    /// Request successful
    RequestSuccessful ( models::InlineResponse200 ) ,
    /// Beacon node internal error.
    BeaconNodeInternalError ,
}

#[derive(Debug, PartialEq)]
pub enum NodeVersionGetResponse {
    /// Request successful
    RequestSuccessful ( String ) ,
    /// Beacon node internal error.
    BeaconNodeInternalError ,
}

#[derive(Debug, PartialEq)]
pub enum ValidatorAttestationGetResponse {
    /// Success response
    SuccessResponse ( models::IndexedAttestation ) ,
    /// Invalid request syntax.
    InvalidRequestSyntax ,
    /// Beacon node internal error.
    BeaconNodeInternalError ,
    /// Beacon node is currently syncing, try again later.
    BeaconNodeIsCurrentlySyncing ,
}

#[derive(Debug, PartialEq)]
pub enum ValidatorAttestationPostResponse {
    /// The attestation was validated successfully and has been broadcast. It has also been integrated into the beacon node's database.
    TheAttestationWasValidatedSuccessfullyAndHasBeenBroadcast ,
    /// The attestation failed validation, but was successfully broadcast anyway. It was not integrated into the beacon node's database.
    TheAttestationFailedValidation ,
    /// Invalid request syntax.
    InvalidRequestSyntax ,
    /// Beacon node internal error.
    BeaconNodeInternalError ,
    /// Beacon node is currently syncing, try again later.
    BeaconNodeIsCurrentlySyncing ,
}

#[derive(Debug, PartialEq)]
pub enum ValidatorBlockGetResponse {
    /// Success response
    SuccessResponse ( models::BeaconBlock ) ,
    /// Invalid request syntax.
    InvalidRequestSyntax ,
    /// Beacon node internal error.
    BeaconNodeInternalError ,
    /// Beacon node is currently syncing, try again later.
    BeaconNodeIsCurrentlySyncing ,
}

#[derive(Debug, PartialEq)]
pub enum ValidatorBlockPostResponse {
    /// The block was validated successfully and has been broadcast. It has also been integrated into the beacon node's database.
    TheBlockWasValidatedSuccessfullyAndHasBeenBroadcast ,
    /// The block failed validation, but was successfully broadcast anyway. It was not integrated into the beacon node's database.
    TheBlockFailedValidation ,
    /// Invalid request syntax.
    InvalidRequestSyntax ,
    /// Beacon node internal error.
    BeaconNodeInternalError ,
    /// Beacon node is currently syncing, try again later.
    BeaconNodeIsCurrentlySyncing ,
}

#[derive(Debug, PartialEq)]
pub enum ValidatorDutiesGetResponse {
    /// Success response
    SuccessResponse ( Vec<models::ValidatorDuty> ) ,
    /// Invalid request syntax.
    InvalidRequestSyntax ,
    /// Duties cannot be provided for the requested epoch.
    DutiesCannotBeProvidedForTheRequestedEpoch ,
    /// Beacon node internal error.
    BeaconNodeInternalError ,
    /// Beacon node is currently syncing, try again later.
    BeaconNodeIsCurrentlySyncing ,
}

#[derive(Debug, PartialEq)]
pub enum NodeForkGetResponse {
    /// Request successful
    RequestSuccessful ( models::InlineResponse2001 ) ,
    /// Beacon node internal error.
    BeaconNodeInternalError ,
}


/// API
pub trait Api<C> {

    /// Get the genesis_time parameter from beacon node configuration.
    fn node_genesis_time_get(&self, context: &C) -> Box<Future<Item=NodeGenesisTimeGetResponse, Error=ApiError>>;

    /// Poll to see if the the beacon node is syncing.
    fn node_syncing_get(&self, context: &C) -> Box<Future<Item=NodeSyncingGetResponse, Error=ApiError>>;

    /// Get version string of the running beacon node.
    fn node_version_get(&self, context: &C) -> Box<Future<Item=NodeVersionGetResponse, Error=ApiError>>;

    /// Produce an attestation, without signature.
    fn validator_attestation_get(&self, validator_pubkey: swagger::ByteArray, poc_bit: i32, slot: i32, shard: i32, context: &C) -> Box<Future<Item=ValidatorAttestationGetResponse, Error=ApiError>>;

    /// Publish a signed attestation.
    fn validator_attestation_post(&self, attestation: models::IndexedAttestation, context: &C) -> Box<Future<Item=ValidatorAttestationPostResponse, Error=ApiError>>;

    /// Produce a new block, without signature.
    fn validator_block_get(&self, slot: i32, randao_reveal: swagger::ByteArray, context: &C) -> Box<Future<Item=ValidatorBlockGetResponse, Error=ApiError>>;

    /// Publish a signed block.
    fn validator_block_post(&self, beacon_block: models::BeaconBlock, context: &C) -> Box<Future<Item=ValidatorBlockPostResponse, Error=ApiError>>;

    /// Get validator duties for the requested validators.
    fn validator_duties_get(&self, validator_pubkeys: &Vec<models::Pubkey>, epoch: Option<i32>, context: &C) -> Box<Future<Item=ValidatorDutiesGetResponse, Error=ApiError>>;

    /// Get fork information from running beacon node.
    fn node_fork_get(&self, context: &C) -> Box<Future<Item=NodeForkGetResponse, Error=ApiError>>;

}

/// API without a `Context`
pub trait ApiNoContext {

    /// Get the genesis_time parameter from beacon node configuration.
    fn node_genesis_time_get(&self) -> Box<Future<Item=NodeGenesisTimeGetResponse, Error=ApiError>>;

    /// Poll to see if the the beacon node is syncing.
    fn node_syncing_get(&self) -> Box<Future<Item=NodeSyncingGetResponse, Error=ApiError>>;

    /// Get version string of the running beacon node.
    fn node_version_get(&self) -> Box<Future<Item=NodeVersionGetResponse, Error=ApiError>>;

    /// Produce an attestation, without signature.
    fn validator_attestation_get(&self, validator_pubkey: swagger::ByteArray, poc_bit: i32, slot: i32, shard: i32) -> Box<Future<Item=ValidatorAttestationGetResponse, Error=ApiError>>;

    /// Publish a signed attestation.
    fn validator_attestation_post(&self, attestation: models::IndexedAttestation) -> Box<Future<Item=ValidatorAttestationPostResponse, Error=ApiError>>;

    /// Produce a new block, without signature.
    fn validator_block_get(&self, slot: i32, randao_reveal: swagger::ByteArray) -> Box<Future<Item=ValidatorBlockGetResponse, Error=ApiError>>;

    /// Publish a signed block.
    fn validator_block_post(&self, beacon_block: models::BeaconBlock) -> Box<Future<Item=ValidatorBlockPostResponse, Error=ApiError>>;

    /// Get validator duties for the requested validators.
    fn validator_duties_get(&self, validator_pubkeys: &Vec<models::Pubkey>, epoch: Option<i32>) -> Box<Future<Item=ValidatorDutiesGetResponse, Error=ApiError>>;

    /// Get fork information from running beacon node.
    fn node_fork_get(&self) -> Box<Future<Item=NodeForkGetResponse, Error=ApiError>>;

}

/// Trait to extend an API to make it easy to bind it to a context.
pub trait ContextWrapperExt<'a, C> where Self: Sized {
    /// Binds this API to a context.
    fn with_context(self: &'a Self, context: C) -> ContextWrapper<'a, Self, C>;
}

impl<'a, T: Api<C> + Sized, C> ContextWrapperExt<'a, C> for T {
    fn with_context(self: &'a T, context: C) -> ContextWrapper<'a, T, C> {
         ContextWrapper::<T, C>::new(self, context)
    }
}

impl<'a, T: Api<C>, C> ApiNoContext for ContextWrapper<'a, T, C> {

    /// Get the genesis_time parameter from beacon node configuration.
    fn node_genesis_time_get(&self) -> Box<Future<Item=NodeGenesisTimeGetResponse, Error=ApiError>> {
        self.api().node_genesis_time_get(&self.context())
    }

    /// Poll to see if the the beacon node is syncing.
    fn node_syncing_get(&self) -> Box<Future<Item=NodeSyncingGetResponse, Error=ApiError>> {
        self.api().node_syncing_get(&self.context())
    }

    /// Get version string of the running beacon node.
    fn node_version_get(&self) -> Box<Future<Item=NodeVersionGetResponse, Error=ApiError>> {
        self.api().node_version_get(&self.context())
    }

    /// Produce an attestation, without signature.
    fn validator_attestation_get(&self, validator_pubkey: swagger::ByteArray, poc_bit: i32, slot: i32, shard: i32) -> Box<Future<Item=ValidatorAttestationGetResponse, Error=ApiError>> {
        self.api().validator_attestation_get(validator_pubkey, poc_bit, slot, shard, &self.context())
    }

    /// Publish a signed attestation.
    fn validator_attestation_post(&self, attestation: models::IndexedAttestation) -> Box<Future<Item=ValidatorAttestationPostResponse, Error=ApiError>> {
        self.api().validator_attestation_post(attestation, &self.context())
    }

    /// Produce a new block, without signature.
    fn validator_block_get(&self, slot: i32, randao_reveal: swagger::ByteArray) -> Box<Future<Item=ValidatorBlockGetResponse, Error=ApiError>> {
        self.api().validator_block_get(slot, randao_reveal, &self.context())
    }

    /// Publish a signed block.
    fn validator_block_post(&self, beacon_block: models::BeaconBlock) -> Box<Future<Item=ValidatorBlockPostResponse, Error=ApiError>> {
        self.api().validator_block_post(beacon_block, &self.context())
    }

    /// Get validator duties for the requested validators.
    fn validator_duties_get(&self, validator_pubkeys: &Vec<models::Pubkey>, epoch: Option<i32>) -> Box<Future<Item=ValidatorDutiesGetResponse, Error=ApiError>> {
        self.api().validator_duties_get(validator_pubkeys, epoch, &self.context())
    }

    /// Get fork information from running beacon node.
    fn node_fork_get(&self) -> Box<Future<Item=NodeForkGetResponse, Error=ApiError>> {
        self.api().node_fork_get(&self.context())
    }

}

#[cfg(feature = "client")]
pub mod client;

// Re-export Client as a top-level name
#[cfg(feature = "client")]
pub use self::client::Client;

#[cfg(feature = "server")]
pub mod server;

// Re-export router() as a top-level name
#[cfg(feature = "server")]
pub use self::server::Service;

pub mod models;
