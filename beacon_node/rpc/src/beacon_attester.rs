use crate::beacon_chain::BeaconChain;
use futures::Future;
use grpcio::{RpcContext, UnarySink, RpcStatus, RpcStatusCode};
use protos::services::{
    AttestationData as AttestationDataProto, ProduceAttestationData, ProduceAttestationDataResponse,
    ProduceAttestationDataRequest, PublishAttestationResponse, PublishAttestationRequest,
    PublishAttestation
};
use protos::services_grpc::BeaconBlockService;
use slog::{Logger, info, warn, error};

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
        info!(&self.log, "Attempting to produce attestation at slot {}", req.get_slot());

        // get the chain spec & state
        let spec = self.chain.get_spec();
        let state = self.chain.get_state();

        // Start by performing some checks
        // Check that the the AttestionData is for the current slot (otherwise it will not be valid)
        if req.get_slot() != state.slot {
            let f = sink
                .fail(RpcStatus::new(
                    RpcStatusCode::OutOfRange,
                    "AttestationData request for a slot that is not the current slot."
                ))
                .map_err(move |e| error!(&self.log, "Failed to reply with failure {:?}: {:?}", req, e));
        }

        // Then collect the data we need for the AttesatationData object
        //let beacon_block_root = state.latest_block_roots.first().ok_or_else(|e| )

        // And finally build the AttestationData object
        let mut attestation_data = AttestationDataProto::new();
        attestation_data.set_slot(state.slot.as_u64());
        attestation_data.set_shard(spec.genesis_start_shard);
        attestation_data.set_beacon_block_root(b"cats".to_vec());
        //attestation_data.

        let mut resp = ProduceAttestationDataResponse::new();
        resp.set_attestation_data(attestation_data);

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
