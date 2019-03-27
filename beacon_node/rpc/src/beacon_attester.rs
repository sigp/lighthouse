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

const TEST_SHARD_PHASE_ZERO: u8 = 0;

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

        let slot_requested = req.get_slot();

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

        // Then get the AttestationData from the beacon chain (for shard 0 for now)
        let attestation_data = self.chain.produce_attestation_data(TEST_SHARD_PHASE_ZERO);

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
