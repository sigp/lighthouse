use protos::services::{
    BeaconBlock as GrpcBeaconBlock, ProduceBeaconBlockRequest, PublishBeaconBlockRequest,
};
use protos::services_grpc::BeaconBlockServiceClient;
use ssz::{ssz_encode, Decodable};
use types::{BeaconBlock, BeaconBlockBody, Hash256, Signature};

#[derive(Debug, PartialEq)]
pub enum BeaconNodeError {
    RemoteFailure(String),
    DecodeFailure,
}

pub trait BeaconNode {
    fn produce_beacon_block(&self, slot: u64) -> Result<Option<BeaconBlock>, BeaconNodeError>;
    fn publish_beacon_block(&self, block: BeaconBlock) -> Result<bool, BeaconNodeError>;
}

impl BeaconNode for BeaconBlockServiceClient {
    fn produce_beacon_block(&self, slot: u64) -> Result<Option<BeaconBlock>, BeaconNodeError> {
        let mut req = ProduceBeaconBlockRequest::new();
        req.set_slot(slot);

        let reply = self
            .produce_beacon_block(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        if reply.has_block() {
            let block = reply.get_block();

            let (signature, _) = Signature::ssz_decode(block.get_signature(), 0)
                .map_err(|_| BeaconNodeError::DecodeFailure)?;

            // TODO: this conversion is incomplete; fix it.
            Ok(Some(BeaconBlock {
                slot: block.get_slot(),
                parent_root: Hash256::zero(),
                state_root: Hash256::zero(),
                randao_reveal: Hash256::from(block.get_randao_reveal()),
                candidate_pow_receipt_root: Hash256::zero(),
                signature,
                body: BeaconBlockBody {
                    proposer_slashings: vec![],
                    casper_slashings: vec![],
                    attestations: vec![],
                    deposits: vec![],
                    exits: vec![],
                },
            }))
        } else {
            Ok(None)
        }
    }

    fn publish_beacon_block(&self, block: BeaconBlock) -> Result<bool, BeaconNodeError> {
        let mut req = PublishBeaconBlockRequest::new();

        // TODO: this conversion is incomplete; fix it.
        let mut grpc_block = GrpcBeaconBlock::new();
        grpc_block.set_slot(block.slot);
        grpc_block.set_block_root(vec![0]);
        grpc_block.set_randao_reveal(block.randao_reveal.to_vec());
        grpc_block.set_signature(ssz_encode(&block.signature));

        req.set_block(grpc_block);

        let reply = self
            .publish_beacon_block(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        Ok(reply.get_success())
    }
}
