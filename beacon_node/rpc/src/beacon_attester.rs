use crate::beacon_chain::BeaconChain;
use futures::Future;
use grpcio::{RpcContext, UnarySink, RpcStatus, RpcStatusCode};
use protos::services::{
    AttestationData as AttestationDataProto, ProduceAttestationData, ProduceAttestationDataResponse,
    ProduceAttestationDataRequest, PublishAttestationResponse, PublishAttestationRequest,
    PublishAttestation
};
use protos::services_grpc::BeaconBlockService;
use slog::{Logger, info, warn, error, trace};

#[derive(Clone)]
pub struct AttestationServiceInstance {
    pub chain: Arc<BeaconChain>,
    pub log: Logger,
}

impl AttestationService for AttestationServiceInstance {
    /// Produce the `AttestationData` for signing by a validator.
    fn produce_attestation_data(
        &mut self,
        ctx: RpcContext,
        req: ProduceAttestationDataRequest,
        sink: UnarySink<ProduceAttestationDataResponse>,
    ) {
        trace!(&self.log, "Attempting to produce attestation at slot {}", req.get_slot());

        // verify the slot, drop lock on state afterwards
        {
            let slot_requested = req.get_slot();
            let state = self.chain.get_state();

            // Start by performing some checks
            // Check that the the AttestionData is for the current slot (otherwise it will not be valid)
            if slot_requested != state.slot {
                let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::OutOfRange,
                        "AttestationData request for a slot that is not the current slot."
                    ))
                    .map_err(move |e| error!(&self.log, "Failed to reply with failure {:?}: {:?}", req, e));
            }
        }

        // Then get the AttestationData from the beacon chain
        let attestation_data = match self.chain.produce_attestation_data(req.get_shard()){
            Ok(v) => v,
            Err(e) => {
                // Could not produce an attestation
                let log_clone = self.log.clone();
                let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::Unknown
                        Some(format!("Could not produce an attestation: {:?}",e)),
                    ))
                    .map_err(move |e| warn!(log_clone, "failed to reply {:?}: {:?}", req, e));
                return ctx.spawn(f);
            }
        };


        let mut attestation_data_proto = AttestationDataProto::new();
        attestation_data_proto.set_ssz(ssz_encode(&attestation_data));

        let mut resp = ProduceAttestationDataResponse::new();
        resp.set_attestation_data(attestation_data_proto);

        let f = sink
            .success(resp)
            .map_err(move |e| error!("Failed to reply with success {:?}: {:?}", req, e));
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

        let attestation = match Attestation::ssz_decode(ssz_serialized_attestation, 0) {
                Ok((v, _index)) => v,
                Err(_) => {
                    let log_clone = self.log.clone();
                    let f = sink
                        .fail(RpcStatus::new(
                            RpcStatusCode::InvalidArgument,
                            Some("Invalid attestation".to_string()),
                        ))
                        .map_err(move |e| warn!(log_clone, "failed to reply {:?}", req));
                    return ctx.spawn(f);
                }
        };

                match self.chain.process_attestation(attestation) {
                    Ok(_) => {
                            // Attestation was successfully processed.
                            info!(
                                self.log,
                                "PublishAttestation";
                                "type" => "valid_attestation",
                            );

                            resp.set_success(true);
                            },
                      Err(e)=> {
                            // Attestation was invalid
                            warn!(
                                self.log,
                                "PublishAttestation";
                                "type" => "invalid_attestation",
                            );
                            resp.set_success(false);
                            resp.set_msg(
                                format!("InvalidAttestation: {:?}", e).as_bytes().to_vec(),
                            );
                            }
                    };

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}
