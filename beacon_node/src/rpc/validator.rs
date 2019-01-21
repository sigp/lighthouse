use futures::Future;
use grpcio::{RpcContext, UnarySink};
use protos::services::{
    IndexResponse, ProposeBlockSlotRequest, ProposeBlockSlotResponse, PublicKey as PublicKeyRequest,
};
use protos::services_grpc::ValidatorService;
use slog::{debug, Logger};

#[derive(Clone)]
pub struct ValidatorServiceInstance {
    pub log: Logger,
}

impl ValidatorService for ValidatorServiceInstance {
    fn validator_index(
        &mut self,
        ctx: RpcContext,
        req: PublicKeyRequest,
        sink: UnarySink<IndexResponse>,
    ) {
        debug!(self.log, "RPC got ValidatorIndex"; "public_key" => format!("{:x?}", req.get_public_key()));

        let mut resp = IndexResponse::new();

        // TODO: return a legit value.
        resp.set_index(1);

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }

    fn propose_block_slot(
        &mut self,
        ctx: RpcContext,
        req: ProposeBlockSlotRequest,
        sink: UnarySink<ProposeBlockSlotResponse>,
    ) {
        debug!(self.log, "RPC got ProposeBlockSlot"; "epoch" => req.get_epoch(), "validator_index" => req.get_validator_index());

        let mut resp = ProposeBlockSlotResponse::new();

        // TODO: return a legit value.
        resp.set_slot(1);

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}
