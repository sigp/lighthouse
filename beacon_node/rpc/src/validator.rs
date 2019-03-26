use bls::PublicKey;
use futures::Future;
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use protos::services::{
    IndexResponse, ProposeBlockSlotRequest, ProposeBlockSlotResponse, PublicKey as PublicKeyRequest,
};
use protos::services_grpc::ValidatorService;
use slog::{debug, Logger};
use ssz::decode;

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
        if let Ok(public_key) = decode::<PublicKey>(req.get_public_key()) {
            debug!(self.log, "RPC request"; "endpoint" => "ValidatorIndex", "public_key" => public_key.concatenated_hex_id());

            let mut resp = IndexResponse::new();

            // TODO: return a legit value.
            resp.set_index(1);

            let f = sink
                .success(resp)
                .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
            ctx.spawn(f)
        } else {
            let f = sink
                .fail(RpcStatus::new(
                    RpcStatusCode::InvalidArgument,
                    Some("Invalid public_key".to_string()),
                ))
                .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
            ctx.spawn(f)
        }
    }

    fn propose_block_slot(
        &mut self,
        ctx: RpcContext,
        req: ProposeBlockSlotRequest,
        sink: UnarySink<ProposeBlockSlotResponse>,
    ) {
        debug!(self.log, "RPC request"; "endpoint" => "ProposeBlockSlot", "epoch" => req.get_epoch(), "validator_index" => req.get_validator_index());

        let mut resp = ProposeBlockSlotResponse::new();

        // TODO: return a legit value.
        resp.set_slot(1);

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}
