use block_proposer::{BeaconNode, BeaconNodeError, PublishOutcome};
use protos::services::{
    BeaconBlock as GrpcBeaconBlock, ProduceBeaconBlockRequest, PublishBeaconBlockRequest,
};
use protos::services_grpc::BeaconBlockServiceClient;
use ssz::{decode, ssz_encode};
use std::sync::Arc;
use types::{BeaconBlock, Signature, Slot};

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

impl BeaconNode for BeaconBlockGrpcClient {
    /// Request a Beacon Node (BN) to produce a new block at the supplied slot.
    ///
    /// Returns `None` if it is not possible to produce at the supplied slot. For example, if the
    /// BN is unable to find a parent block.
    fn produce_beacon_block(
        &self,
        slot: Slot,
        // TODO: use randao_reveal, when proto APIs have been updated.
        _randao_reveal: &Signature,
    ) -> Result<Option<BeaconBlock>, BeaconNodeError> {
        let mut req = ProduceBeaconBlockRequest::new();
        req.set_slot(slot.as_u64());

        let reply = self
            .client
            .produce_beacon_block(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        if reply.has_block() {
            let block = reply.get_block();
            let ssz = block.get_ssz();

            let block = decode::<BeaconBlock>(&ssz).map_err(|_| BeaconNodeError::DecodeFailure)?;

            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    /// Request a Beacon Node (BN) to publish a block.
    ///
    /// Generally, this will be called after a `produce_beacon_block` call with a block that has
    /// been completed (signed) by the validator client.
    fn publish_beacon_block(&self, block: BeaconBlock) -> Result<PublishOutcome, BeaconNodeError> {
        let mut req = PublishBeaconBlockRequest::new();

        let ssz = ssz_encode(&block);

        // TODO: this conversion is incomplete; fix it.
        let mut grpc_block = GrpcBeaconBlock::new();
        grpc_block.set_ssz(ssz);

        req.set_block(grpc_block);

        let reply = self
            .client
            .publish_beacon_block(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        if reply.get_success() {
            Ok(PublishOutcome::ValidBlock)
        } else {
            // TODO: distinguish between different errors
            Ok(PublishOutcome::InvalidBlock("Publish failed".to_string()))
        }
    }
}
