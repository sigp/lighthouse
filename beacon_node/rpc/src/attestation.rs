use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::PubsubMessage;
use eth2_libp2p::TopicBuilder;
use futures::Future;
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use network::NetworkMessage;
use protos::services::{
    AttestationData as AttestationDataProto, ProduceAttestationDataRequest,
    ProduceAttestationDataResponse, PublishAttestationRequest, PublishAttestationResponse,
};
use protos::services_grpc::AttestationService;
use slog::{error, info, trace, warn};
use ssz::{ssz_encode, Decode};
use std::sync::Arc;
use types::Attestation;

#[derive(Clone)]
pub struct AttestationServiceInstance<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    pub network_chan: crossbeam_channel::Sender<NetworkMessage>,
    pub log: slog::Logger,
}

impl<T: BeaconChainTypes> AttestationService for AttestationServiceInstance<T> {
    /// Produce the `AttestationData` for signing by a validator.
    fn produce_attestation_data(
        &mut self,
        ctx: RpcContext,
        req: ProduceAttestationDataRequest,
        sink: UnarySink<ProduceAttestationDataResponse>,
    ) {
        trace!(
            &self.log,
            "Attempting to produce attestation at slot {}",
            req.get_slot()
        );

        // verify the slot, drop lock on state afterwards
        {
            let slot_requested = req.get_slot();
            let state = &self.chain.current_state();

            // Start by performing some checks
            // Check that the AttestionData is for the current slot (otherwise it will not be valid)
            if slot_requested > state.slot.as_u64() {
                let log_clone = self.log.clone();
                let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::OutOfRange,
                        Some(
                            "AttestationData request for a slot that is in the future.".to_string(),
                        ),
                    ))
                    .map_err(move |e| {
                        error!(log_clone, "Failed to reply with failure {:?}: {:?}", req, e)
                    });
                return ctx.spawn(f);
            }
            // currently cannot handle past slots. TODO: Handle this case
            else if slot_requested < state.slot.as_u64() {
                let log_clone = self.log.clone();
                let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::InvalidArgument,
                        Some("AttestationData request for a slot that is in the past.".to_string()),
                    ))
                    .map_err(move |e| {
                        error!(log_clone, "Failed to reply with failure {:?}: {:?}", req, e)
                    });
                return ctx.spawn(f);
            }
        }

        // Then get the AttestationData from the beacon chain
        let shard = req.get_shard();
        let attestation_data = match self.chain.produce_attestation_data(shard) {
            Ok(v) => v,
            Err(e) => {
                // Could not produce an attestation
                let log_clone = self.log.clone();
                let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::Unknown,
                        Some(format!("Could not produce an attestation: {:?}", e)),
                    ))
                    .map_err(move |e| warn!(log_clone, "failed to reply {:?}: {:?}", req, e));
                return ctx.spawn(f);
            }
        };

        let mut attestation_data_proto = AttestationDataProto::new();
        attestation_data_proto.set_ssz(ssz_encode(&attestation_data));

        let mut resp = ProduceAttestationDataResponse::new();
        resp.set_attestation_data(attestation_data_proto);

        let error_log = self.log.clone();
        let f = sink
            .success(resp)
            .map_err(move |e| error!(error_log, "Failed to reply with success {:?}: {:?}", req, e));
        ctx.spawn(f)
    }

    /// Accept some fully-formed `FreeAttestation` from the validator,
    /// store it, and aggregate it into an `Attestation`.
    fn publish_attestation(
        &mut self,
        ctx: RpcContext,
        req: PublishAttestationRequest,
        sink: UnarySink<PublishAttestationResponse>,
    ) {
        trace!(self.log, "Publishing attestation");

        let mut resp = PublishAttestationResponse::new();
        let ssz_serialized_attestation = req.get_attestation().get_ssz();

        let attestation = match Attestation::from_ssz_bytes(ssz_serialized_attestation) {
            Ok(v) => v,
            Err(_) => {
                let log_clone = self.log.clone();
                let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::InvalidArgument,
                        Some("Invalid attestation".to_string()),
                    ))
                    .map_err(move |_| warn!(log_clone, "failed to reply {:?}", req));
                return ctx.spawn(f);
            }
        };

        match self.chain.process_attestation(attestation.clone()) {
            Ok(_) => {
                // Attestation was successfully processed.
                info!(
                    self.log,
                    "PublishAttestation";
                    "type" => "valid_attestation",
                );

                // get the network topic to send on
                let topic_string = self.chain.get_spec().shard_topic_prefix.clone();

                // valid attestation, propagate to the network
                let topic = TopicBuilder::new(topic_string).build();
                let message = PubsubMessage::Attestation(attestation);

                self.network_chan
                    .send(NetworkMessage::Publish {
                        topics: vec![topic],
                        message: Box::new(message),
                    })
                    .unwrap_or_else(|e| {
                        error!(
                            self.log,
                            "PublishAttestation";
                            "type" => "failed to publish attestation to gossipsub",
                            "error" => format!("{:?}", e)
                        );
                    });

                resp.set_success(true);
            }
            Err(e) => {
                // Attestation was invalid
                warn!(
                    self.log,
                    "PublishAttestation";
                    "type" => "invalid_attestation",
                    "error" => format!("{:?}", e),
                );
                resp.set_success(false);
                resp.set_msg(format!("InvalidAttestation: {:?}", e).as_bytes().to_vec());
            }
        };

        let error_log = self.log.clone();
        let f = sink
            .success(resp)
            .map_err(move |e| error!(error_log, "failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}
