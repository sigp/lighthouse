use block_proposer::{BeaconNode, BeaconNodeError, PublishOutcome};
use protos::services::{
    BeaconBlock as GrpcBeaconBlock, ProduceBeaconBlockRequest, PublishBeaconBlockRequest,
};
use protos::services_grpc::BeaconBlockServiceClient;
use ssz::{decode, ssz_encode};
use std::sync::Arc;
use types::{BeaconBlock, BeaconBlockBody, Eth1Data, Hash256, Signature, Slot};

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

            let signature = decode::<Signature>(block.get_signature())
                .map_err(|_| BeaconNodeError::DecodeFailure)?;

            let randao_reveal = decode::<Signature>(block.get_randao_reveal())
                .map_err(|_| BeaconNodeError::DecodeFailure)?;

            // TODO: this conversion is incomplete; fix it.
            Ok(Some(BeaconBlock {
                slot: Slot::new(block.get_slot()),
                parent_root: Hash256::zero(),
                state_root: Hash256::zero(),
                randao_reveal,
                eth1_data: Eth1Data {
                    deposit_root: Hash256::zero(),
                    block_hash: Hash256::zero(),
                },
                signature,
                body: BeaconBlockBody {
                    proposer_slashings: vec![],
                    attester_slashings: vec![],
                    attestations: vec![],
                    deposits: vec![],
                    voluntary_exits: vec![],
                    transfers: vec![],
                },
            }))
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

        // TODO: this conversion is incomplete; fix it.
        let mut grpc_block = GrpcBeaconBlock::new();
        grpc_block.set_slot(block.slot.as_u64());
        grpc_block.set_block_root(vec![0]);
        grpc_block.set_randao_reveal(ssz_encode(&block.randao_reveal));
        grpc_block.set_signature(ssz_encode(&block.signature));

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
