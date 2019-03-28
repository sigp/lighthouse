use crate::beacon_chain::BeaconChain;
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
use slog::{debug, error, info, warn};
use ssz::{Decodable, TreeHash};
use std::sync::Arc;
use types::{BeaconBlock, Hash256, Slot};

#[derive(Clone)]
pub struct BeaconBlockServiceInstance {
    pub chain: Arc<BeaconChain>,
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
        block.set_ssz(b"cats".to_vec());

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
        let mut resp = PublishBeaconBlockResponse::new();

        let ssz_serialized_block = req.get_block().get_ssz();

        match BeaconBlock::ssz_decode(ssz_serialized_block, 0) {
            Ok((block, _i)) => {
                let block_root = Hash256::from_slice(&block.hash_tree_root()[..]);

                match self.chain.process_block(block.clone()) {
                    Ok(outcome) => {
                        if outcome.sucessfully_processed() {
                            // Block was successfully processed.
                            info!(
                                self.log,
                                "PublishBeaconBlock";
                                "type" => "valid_block",
                                "block_slot" => block.slot,
                                "outcome" => format!("{:?}", outcome)
                            );

                            // TODO: Obtain topics from the network service properly.
                            let topic =
                                types::TopicBuilder::new("beacon_chain".to_string()).build();
                            let message = PubsubMessage::Block(BlockRootSlot {
                                block_root,
                                slot: block.slot,
                            });

                            println!("Sending beacon block to gossipsub");
                            self.network_chan.send(NetworkMessage::Publish {
                                topics: vec![topic],
                                message,
                            });

                            resp.set_success(true);
                        } else if outcome.is_invalid() {
                            // Block was invalid.
                            warn!(
                                self.log,
                                "PublishBeaconBlock";
                                "type" => "invalid_block",
                                "outcome" => format!("{:?}", outcome)
                            );

                            resp.set_success(false);
                            resp.set_msg(
                                format!("InvalidBlock: {:?}", outcome).as_bytes().to_vec(),
                            );
                        } else {
                            // Some failure during processing.
                            warn!(
                                self.log,
                                "PublishBeaconBlock";
                                "type" => "unable_to_import",
                                "outcome" => format!("{:?}", outcome)
                            );

                            resp.set_success(false);
                            resp.set_msg(format!("other: {:?}", outcome).as_bytes().to_vec());
                        }
                    }
                    Err(e) => {
                        // Some failure during processing.
                        error!(
                            self.log,
                            "PublishBeaconBlock";
                            "type" => "failed_to_process",
                            "error" => format!("{:?}", e)
                        );

                        resp.set_success(false);
                        resp.set_msg(format!("failed_to_process: {:?}", e).as_bytes().to_vec());
                    }
                }

                resp.set_success(true);
            }
            Err(_) => {
                resp.set_success(false);
                resp.set_msg(b"Invalid SSZ".to_vec());
            }
        };

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}
