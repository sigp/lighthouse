use futures::Future;
use grpcio::{RpcContext, UnarySink};
use protos::services::{
    Attestation as AttestationProto, ProduceAttestation, ProduceAttestationResponse,
    ProduceAttestationRequest, PublishAttestationResponse, PublishAttestationRequest,
    PublishAttestation
};
use protos::services_grpc::BeaconBlockService;
use slog::Logger;

#[derive(Clone)]
pub struct AttestationServiceInstance {
    pub log: Logger,
}

impl AttestationService for AttestationServiceInstance {
    /// Produce a `BeaconBlock` for signing by a validator.
    fn produce_attestation(
        &mut self,
        ctx: RpcContext,
        req: ProduceAttestationRequest,
        sink: UnarySink<ProduceAttestationResponse>,
    ) {
        println!("producing attestation at slot {}", req.get_slot());

        // TODO: build a legit block.
        let mut attestation = AttestationProto::new();
        attestation.set_slot(req.get_slot());
        // TODO Set the shard to something legit.
        attestation.set_shard(0);
        attestation.set_block_root(b"cats".to_vec());

        let mut resp = ProduceAttestationResponse::new();
        resp.set_attestation_data(attestation);

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }

    /// Accept some fully-formed `BeaconBlock`, process and publish it.
    fn publish_attestation(
        &mut self,
        ctx: RpcContext,
        req: PublishAttestationRequest,
        sink: UnarySink<PublishAttestationResponse>,
    ) {
        println!("publishing attestation {:?}", req.get_block());

        // TODO: actually process the block.
        let mut resp = PublishAttestationResponse::new();

        resp.set_success(true);

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}
