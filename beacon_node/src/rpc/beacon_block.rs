use futures::Future;
use grpcio::{RpcContext, UnarySink};
use protos::services::{
    BeaconBlock as BeaconBlockProto, ProduceBeaconBlockRequest, ProduceBeaconBlockResponse,
    PublishBeaconBlockRequest, PublishBeaconBlockResponse,
};
use protos::services_grpc::BeaconBlockService;
use slog::Logger;

#[derive(Clone)]
pub struct BeaconBlockServiceInstance {
    pub log: Logger,
}

impl BeaconBlockService for BeaconBlockServiceInstance {
    /// Produce a `BeaconBlock` for signing by a validator.
    fn produce_beacon_block(
        &mut self,
        ctx: RpcContext,
        req: ProduceBeaconBlockRequest,
        sink: UnarySink<ProduceBeaconBlockResponse>,
    ) {
        println!("producing at slot {}", req.get_slot());

        // TODO: build a legit block.
        let mut block = BeaconBlockProto::new();
        block.set_slot(req.get_slot());
        block.set_block_root("cats".as_bytes().to_vec());

        let mut resp = ProduceBeaconBlockResponse::new();
        resp.set_block(block);

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }

    /// Accept some fully-formed `BeaconBlock`, process and publish it.
    fn publish_beacon_block(
        &mut self,
        ctx: RpcContext,
        req: PublishBeaconBlockRequest,
        sink: UnarySink<PublishBeaconBlockResponse>,
    ) {
        println!("publishing {:?}", req.get_block());

        // TODO: actually process the block.
        let mut resp = PublishBeaconBlockResponse::new();
        resp.set_success(true);

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}
