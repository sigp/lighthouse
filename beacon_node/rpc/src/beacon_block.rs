use crate::beacon_chain::BeaconChain;
use crossbeam_channel;
use eth2_libp2p::PubsubMessage;
use futures::Future;
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use network::NetworkMessage;
use protos::services::{
    BeaconBlock as BeaconBlockProto, ProduceBeaconBlockRequest, ProduceBeaconBlockResponse,
    PublishBeaconBlockRequest, PublishBeaconBlockResponse,
};
use protos::services_grpc::BeaconBlockService;
use slog::Logger;
use slog::{error, info, trace, warn};
use ssz::{ssz_encode, Decodable};
use std::sync::Arc;
use types::{BeaconBlock, BeaconStateTypes, Signature, Slot};

#[derive(Clone)]
pub struct BeaconBlockServiceInstance<B: BeaconStateTypes> {
    pub chain: Arc<BeaconChain<B>>,
    pub network_chan: crossbeam_channel::Sender<NetworkMessage>,
    pub log: Logger,
}

impl<B: BeaconStateTypes> BeaconBlockService for BeaconBlockServiceInstance<B> {
    /// Produce a `BeaconBlock` for signing by a validator.
    fn produce_beacon_block(
        &mut self,
        ctx: RpcContext,
        req: ProduceBeaconBlockRequest,
        sink: UnarySink<ProduceBeaconBlockResponse>,
    ) {
        trace!(self.log, "Generating a beacon block"; "req" => format!("{:?}", req));

        // decode the request
        // TODO: requested slot currently unused, see: https://github.com/sigp/lighthouse/issues/336
        let _requested_slot = Slot::from(req.get_slot());
        let randao_reveal = match Signature::ssz_decode(req.get_randao_reveal(), 0) {
            Ok((reveal, _index)) => reveal,
            Err(_) => {
                // decode error, incorrect signature
                let log_clone = self.log.clone();
                let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::InvalidArgument,
                        Some("Invalid randao reveal signature".to_string()),
                    ))
                    .map_err(move |e| warn!(log_clone, "failed to reply {:?}: {:?}", req, e));
                return ctx.spawn(f);
            }
        };

        let produced_block = match self.chain.produce_block(randao_reveal) {
            Ok((block, _state)) => block,
            Err(e) => {
                // could not produce a block
                let log_clone = self.log.clone();
                warn!(self.log, "RPC Error"; "Error" => format!("Could not produce a block:{:?}",e));
                let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::Unknown,
                        Some(format!("Could not produce a block: {:?}", e)),
                    ))
                    .map_err(move |e| warn!(log_clone, "failed to reply {:?}: {:?}", req, e));
                return ctx.spawn(f);
            }
        };

        let mut block = BeaconBlockProto::new();
        block.set_ssz(ssz_encode(&produced_block));

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
        trace!(&self.log, "Attempting to publish a block");

        let mut resp = PublishBeaconBlockResponse::new();

        let ssz_serialized_block = req.get_block().get_ssz();

        match BeaconBlock::ssz_decode(ssz_serialized_block, 0) {
            Ok((block, _i)) => {
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
                            let message = PubsubMessage::Block(block);

                            // Publish the block to the p2p network via gossipsub.
                            self.network_chan
                                .send(NetworkMessage::Publish {
                                    topics: vec![topic],
                                    message: Box::new(message),
                                })
                                .unwrap_or_else(|e| {
                                    error!(
                                        self.log,
                                        "PublishBeaconBlock";
                                        "type" => "failed to publish to gossipsub",
                                        "error" => format!("{:?}", e)
                                    );
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
