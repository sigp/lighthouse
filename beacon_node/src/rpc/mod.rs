use std::sync::Arc;

use futures::Future;
use grpcio::{Environment, RpcContext, Server, ServerBuilder, UnarySink};

use protos::services::{
    BeaconBlock as BeaconBlockProto, ProduceBeaconBlockRequest, ProduceBeaconBlockResponse,
    PublishBeaconBlockRequest, PublishBeaconBlockResponse,
};
use protos::services_grpc::{create_beacon_block_service, BeaconBlockService};

use slog::{info, Logger};

#[derive(Clone)]
struct BeaconBlockServiceInstance {
    log: Logger,
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

pub fn start_server(log: Logger) -> Server {
    let log_clone = log.clone();

    let env = Arc::new(Environment::new(1));
    let instance = BeaconBlockServiceInstance { log };
    let service = create_beacon_block_service(instance);
    let mut server = ServerBuilder::new(env)
        .register_service(service)
        .bind("127.0.0.1", 50_051)
        .build()
        .unwrap();
    server.start();
    for &(ref host, port) in server.bind_addrs() {
        info!(log_clone, "gRPC listening on {}:{}", host, port);
    }
    server
}
