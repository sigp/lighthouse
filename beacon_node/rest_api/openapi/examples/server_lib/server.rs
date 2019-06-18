//! Server implementation of openapi_client.

#![allow(unused_imports)]

use futures::{self, Future};
use chrono;
use std::collections::HashMap;
use std::marker::PhantomData;

use swagger;
use swagger::{Has, XSpanIdString};

use openapi_client::{Api, ApiError,
                      NodeGenesisTimeGetResponse,
                      NodeSyncingGetResponse,
                      NodeVersionGetResponse,
                      ValidatorAttestationGetResponse,
                      ValidatorAttestationPostResponse,
                      ValidatorBlockGetResponse,
                      ValidatorBlockPostResponse,
                      ValidatorDutiesGetResponse,
                      NodeForkGetResponse
};
use openapi_client::models;

#[derive(Copy, Clone)]
pub struct Server<C> {
    marker: PhantomData<C>,
}

impl<C> Server<C> {
    pub fn new() -> Self {
        Server{marker: PhantomData}
    }
}

impl<C> Api<C> for Server<C> where C: Has<XSpanIdString>{

    /// Get the genesis_time parameter from beacon node configuration.
    fn node_genesis_time_get(&self, context: &C) -> Box<Future<Item=NodeGenesisTimeGetResponse, Error=ApiError>> {
        let context = context.clone();
        println!("node_genesis_time_get() - X-Span-ID: {:?}", context.get().0.clone());
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Poll to see if the the beacon node is syncing.
    fn node_syncing_get(&self, context: &C) -> Box<Future<Item=NodeSyncingGetResponse, Error=ApiError>> {
        let context = context.clone();
        println!("node_syncing_get() - X-Span-ID: {:?}", context.get().0.clone());
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Get version string of the running beacon node.
    fn node_version_get(&self, context: &C) -> Box<Future<Item=NodeVersionGetResponse, Error=ApiError>> {
        let context = context.clone();
        println!("node_version_get() - X-Span-ID: {:?}", context.get().0.clone());
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Produce an attestation, without signature.
    fn validator_attestation_get(&self, validator_pubkey: swagger::ByteArray, poc_bit: i32, slot: i32, shard: i32, context: &C) -> Box<Future<Item=ValidatorAttestationGetResponse, Error=ApiError>> {
        let context = context.clone();
        println!("validator_attestation_get({:?}, {}, {}, {}) - X-Span-ID: {:?}", validator_pubkey, poc_bit, slot, shard, context.get().0.clone());
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Publish a signed attestation.
    fn validator_attestation_post(&self, attestation: models::IndexedAttestation, context: &C) -> Box<Future<Item=ValidatorAttestationPostResponse, Error=ApiError>> {
        let context = context.clone();
        println!("validator_attestation_post({:?}) - X-Span-ID: {:?}", attestation, context.get().0.clone());
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Produce a new block, without signature.
    fn validator_block_get(&self, slot: i32, randao_reveal: swagger::ByteArray, context: &C) -> Box<Future<Item=ValidatorBlockGetResponse, Error=ApiError>> {
        let context = context.clone();
        println!("validator_block_get({}, {:?}) - X-Span-ID: {:?}", slot, randao_reveal, context.get().0.clone());
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Publish a signed block.
    fn validator_block_post(&self, beacon_block: models::BeaconBlock, context: &C) -> Box<Future<Item=ValidatorBlockPostResponse, Error=ApiError>> {
        let context = context.clone();
        println!("validator_block_post({:?}) - X-Span-ID: {:?}", beacon_block, context.get().0.clone());
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Get validator duties for the requested validators.
    fn validator_duties_get(&self, validator_pubkeys: &Vec<models::Pubkey>, epoch: Option<i32>, context: &C) -> Box<Future<Item=ValidatorDutiesGetResponse, Error=ApiError>> {
        let context = context.clone();
        println!("validator_duties_get({:?}, {:?}) - X-Span-ID: {:?}", validator_pubkeys, epoch, context.get().0.clone());
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Get fork information from running beacon node.
    fn node_fork_get(&self, context: &C) -> Box<Future<Item=NodeForkGetResponse, Error=ApiError>> {
        let context = context.clone();
        println!("node_fork_get() - X-Span-ID: {:?}", context.get().0.clone());
        Box::new(futures::failed("Generic failure".into()))
    }

}
