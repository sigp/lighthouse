use crossbeam_channel;
use eth2_libp2p::rpc::methods::BlockRootSlot;
use eth2_libp2p::PubsubMessage;
use futures::Future;
use grpcio::{RpcContext, UnarySink};
use network::NetworkMessage;
use protos::services::{
    BeaconBlock as BeaconBlockProto, ProduceBeaconBlockRequest, ProduceBeaconBlockResponse,
    PublishBeaconBlockRequest, PublishBeaconBlockResponse,
};
use protos::services_grpc::BeaconBlockService;
use slog::Logger;
use types::{Hash256, Slot};

#[derive(Clone)]
pub struct BeaconBlockServiceInstance {
    pub network_chan: crossbeam_channel::Sender<NetworkMessage>,
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
        block.set_block_root(b"cats".to_vec());

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
        let block = req.get_block();
        let block_root = Hash256::from_slice(block.get_block_root());
        let block_slot = BlockRootSlot {
            block_root,
            slot: Slot::from(block.get_slot()),
        };
        println!("publishing block with root {:?}", block_root);

        // TODO: Obtain topics from the network service properly.
        let topic = types::TopicBuilder::new("beacon_chain".to_string()).build();
        let message = PubsubMessage::Block(block_slot);
        println!("Sending beacon block to gossipsub");
        self.network_chan.send(NetworkMessage::Publish {
            topics: vec![topic],
            message,
        });

        // TODO: actually process the block.
        let mut resp = PublishBeaconBlockResponse::new();
        resp.set_success(true);

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}
