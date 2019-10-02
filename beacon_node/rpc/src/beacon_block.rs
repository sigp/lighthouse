use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::{PubsubMessage, Topic};
use eth2_libp2p::{BEACON_BLOCK_TOPIC, TOPIC_ENCODING_POSTFIX, TOPIC_PREFIX};
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
use ssz::{ssz_encode, Decode, Encode};
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{BeaconBlock, Signature, Slot};

#[derive(Clone)]
pub struct BeaconBlockServiceInstance<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    pub network_chan: mpsc::UnboundedSender<NetworkMessage>,
    pub log: Logger,
}

impl<T: BeaconChainTypes> BeaconBlockService for BeaconBlockServiceInstance<T> {
    /// Produce a `BeaconBlock` for signing by a validator.
    fn produce_beacon_block(
        &mut self,
        ctx: RpcContext,
        req: ProduceBeaconBlockRequest,
        sink: UnarySink<ProduceBeaconBlockResponse>,
    ) {
        trace!(self.log, "Generating a beacon block"; "req" => format!("{:?}", req));

        // decode the request
        let requested_slot = Slot::from(req.get_slot());
        let randao_reveal = match Signature::from_ssz_bytes(req.get_randao_reveal()) {
            Ok(reveal) => reveal,
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

        let produced_block = match self.chain.produce_block(randao_reveal, requested_slot) {
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

        assert_eq!(
            produced_block.slot, requested_slot,
            "should produce at the requested slot"
        );

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

        match BeaconBlock::from_ssz_bytes(ssz_serialized_block) {
            Ok(block) => {
                match self.chain.process_block(block.clone()) {
                    Ok(outcome) => {
                        if let BlockProcessingOutcome::Processed { block_root } = outcome {
                            // Block was successfully processed.
                            info!(
                                self.log,
                                "Valid block from RPC";
                                "root" => format!("{}", block_root),
                                "slot" => block.slot,
                            );

                            // create the network topic to send on
                            let topic_string = format!(
                                "/{}/{}/{}",
                                TOPIC_PREFIX, BEACON_BLOCK_TOPIC, TOPIC_ENCODING_POSTFIX
                            );
                            let topic = Topic::new(topic_string);
                            let message = PubsubMessage::Block(block.as_ssz_bytes());

                            // Publish the block to the p2p network via gossipsub.
                            self.network_chan
                                .try_send(NetworkMessage::Publish {
                                    topics: vec![topic],
                                    message,
                                })
                                .unwrap_or_else(|e| {
                                    error!(
                                        self.log,
                                        "Failed to gossip beacon block";
                                        "error" => format!("{:?}", e)
                                    );
                                });

                            resp.set_success(true);
                        } else {
                            // Block was not successfully processed.
                            warn!(
                                self.log,
                                "Invalid block from RPC";
                                "outcome" => format!("{:?}", outcome)
                            );

                            resp.set_success(false);
                            resp.set_msg(
                                format!("InvalidBlock: {:?}", outcome).as_bytes().to_vec(),
                            );
                        }
                    }
                    Err(e) => {
                        // Some failure during processing.
                        error!(
                            self.log,
                            "Failed to process beacon block";
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
