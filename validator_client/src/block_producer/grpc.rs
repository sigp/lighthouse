use super::beacon_node_block::*;
use protos::services::{
    BeaconBlock as GrpcBeaconBlock, ProduceBeaconBlockRequest, PublishBeaconBlockRequest,
};
use protos::services_grpc::BeaconBlockServiceClient;
use ssz::{Decode, Encode};
use std::sync::Arc;
use types::{BeaconBlock, EthSpec, Signature, Slot};

//TODO: Remove this new type. Do not need to wrap
/// A newtype designed to wrap the gRPC-generated service so the `BeaconNode` trait may be
/// implemented upon it.
pub struct BeaconBlockGrpcClient {
    client: Arc<BeaconBlockServiceClient>,
}

impl BeaconBlockGrpcClient {
    pub fn new(client: Arc<BeaconBlockServiceClient>) -> Self {
        Self { client }
    }
}

impl BeaconNodeBlock for BeaconBlockGrpcClient {
    /// Request a Beacon Node (BN) to produce a new block at the supplied slot.
    ///
    /// Returns `None` if it is not possible to produce at the supplied slot. For example, if the
    /// BN is unable to find a parent block.
    fn produce_beacon_block<T: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &Signature,
    ) -> Result<Option<BeaconBlock<T>>, BeaconNodeError> {
        // request a beacon block from the node
        let mut req = ProduceBeaconBlockRequest::new();
        req.set_slot(slot.as_u64());
        req.set_randao_reveal(randao_reveal.as_ssz_bytes());

        //TODO: Determine if we want an explicit timeout
        let reply = self
            .client
            .produce_beacon_block(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        // format the reply
        if reply.has_block() {
            let block = reply.get_block();
            let ssz = block.get_ssz();

            let block =
                BeaconBlock::from_ssz_bytes(&ssz).map_err(|_| BeaconNodeError::DecodeFailure)?;

            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    /// Request a Beacon Node (BN) to publish a block.
    ///
    /// Generally, this will be called after a `produce_beacon_block` call with a block that has
    /// been completed (signed) by the validator client.
    fn publish_beacon_block<T: EthSpec>(
        &self,
        block: BeaconBlock<T>,
    ) -> Result<PublishOutcome, BeaconNodeError> {
        let mut req = PublishBeaconBlockRequest::new();

        let ssz = block.as_ssz_bytes();

        let mut grpc_block = GrpcBeaconBlock::new();
        grpc_block.set_ssz(ssz);

        req.set_block(grpc_block);

        let reply = self
            .client
            .publish_beacon_block(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        if reply.get_success() {
            Ok(PublishOutcome::Valid)
        } else {
            // TODO: distinguish between different errors
            Ok(PublishOutcome::InvalidBlock("Publish failed".to_string()))
        }
    }
}
