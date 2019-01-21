// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

const METHOD_BEACON_BLOCK_SERVICE_PRODUCE_BEACON_BLOCK: ::grpcio::Method<super::services::ProduceBeaconBlockRequest, super::services::ProduceBeaconBlockResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/ethereum.beacon.rpc.v1.BeaconBlockService/ProduceBeaconBlock",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_BEACON_BLOCK_SERVICE_PUBLISH_BEACON_BLOCK: ::grpcio::Method<super::services::PublishBeaconBlockRequest, super::services::PublishBeaconBlockResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/ethereum.beacon.rpc.v1.BeaconBlockService/PublishBeaconBlock",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_BEACON_BLOCK_SERVICE_VALIDATOR_ASSIGNMENT: ::grpcio::Method<super::services::ValidatorAssignmentRequest, super::services::ValidatorAssignmentResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/ethereum.beacon.rpc.v1.BeaconBlockService/ValidatorAssignment",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

#[derive(Clone)]
pub struct BeaconBlockServiceClient {
    client: ::grpcio::Client,
}

impl BeaconBlockServiceClient {
    pub fn new(channel: ::grpcio::Channel) -> Self {
        BeaconBlockServiceClient {
            client: ::grpcio::Client::new(channel),
        }
    }

    pub fn produce_beacon_block_opt(&self, req: &super::services::ProduceBeaconBlockRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::services::ProduceBeaconBlockResponse> {
        self.client.unary_call(&METHOD_BEACON_BLOCK_SERVICE_PRODUCE_BEACON_BLOCK, req, opt)
    }

    pub fn produce_beacon_block(&self, req: &super::services::ProduceBeaconBlockRequest) -> ::grpcio::Result<super::services::ProduceBeaconBlockResponse> {
        self.produce_beacon_block_opt(req, ::grpcio::CallOption::default())
    }

    pub fn produce_beacon_block_async_opt(&self, req: &super::services::ProduceBeaconBlockRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::services::ProduceBeaconBlockResponse>> {
        self.client.unary_call_async(&METHOD_BEACON_BLOCK_SERVICE_PRODUCE_BEACON_BLOCK, req, opt)
    }

    pub fn produce_beacon_block_async(&self, req: &super::services::ProduceBeaconBlockRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::services::ProduceBeaconBlockResponse>> {
        self.produce_beacon_block_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn publish_beacon_block_opt(&self, req: &super::services::PublishBeaconBlockRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::services::PublishBeaconBlockResponse> {
        self.client.unary_call(&METHOD_BEACON_BLOCK_SERVICE_PUBLISH_BEACON_BLOCK, req, opt)
    }

    pub fn publish_beacon_block(&self, req: &super::services::PublishBeaconBlockRequest) -> ::grpcio::Result<super::services::PublishBeaconBlockResponse> {
        self.publish_beacon_block_opt(req, ::grpcio::CallOption::default())
    }

    pub fn publish_beacon_block_async_opt(&self, req: &super::services::PublishBeaconBlockRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::services::PublishBeaconBlockResponse>> {
        self.client.unary_call_async(&METHOD_BEACON_BLOCK_SERVICE_PUBLISH_BEACON_BLOCK, req, opt)
    }

    pub fn publish_beacon_block_async(&self, req: &super::services::PublishBeaconBlockRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::services::PublishBeaconBlockResponse>> {
        self.publish_beacon_block_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn validator_assignment_opt(&self, req: &super::services::ValidatorAssignmentRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::services::ValidatorAssignmentResponse> {
        self.client.unary_call(&METHOD_BEACON_BLOCK_SERVICE_VALIDATOR_ASSIGNMENT, req, opt)
    }

    pub fn validator_assignment(&self, req: &super::services::ValidatorAssignmentRequest) -> ::grpcio::Result<super::services::ValidatorAssignmentResponse> {
        self.validator_assignment_opt(req, ::grpcio::CallOption::default())
    }

    pub fn validator_assignment_async_opt(&self, req: &super::services::ValidatorAssignmentRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::services::ValidatorAssignmentResponse>> {
        self.client.unary_call_async(&METHOD_BEACON_BLOCK_SERVICE_VALIDATOR_ASSIGNMENT, req, opt)
    }

    pub fn validator_assignment_async(&self, req: &super::services::ValidatorAssignmentRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::services::ValidatorAssignmentResponse>> {
        self.validator_assignment_async_opt(req, ::grpcio::CallOption::default())
    }
    pub fn spawn<F>(&self, f: F) where F: ::futures::Future<Item = (), Error = ()> + Send + 'static {
        self.client.spawn(f)
    }
}

pub trait BeaconBlockService {
    fn produce_beacon_block(&mut self, ctx: ::grpcio::RpcContext, req: super::services::ProduceBeaconBlockRequest, sink: ::grpcio::UnarySink<super::services::ProduceBeaconBlockResponse>);
    fn publish_beacon_block(&mut self, ctx: ::grpcio::RpcContext, req: super::services::PublishBeaconBlockRequest, sink: ::grpcio::UnarySink<super::services::PublishBeaconBlockResponse>);
    fn validator_assignment(&mut self, ctx: ::grpcio::RpcContext, req: super::services::ValidatorAssignmentRequest, sink: ::grpcio::UnarySink<super::services::ValidatorAssignmentResponse>);
}

pub fn create_beacon_block_service<S: BeaconBlockService + Send + Clone + 'static>(s: S) -> ::grpcio::Service {
    let mut builder = ::grpcio::ServiceBuilder::new();
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_BEACON_BLOCK_SERVICE_PRODUCE_BEACON_BLOCK, move |ctx, req, resp| {
        instance.produce_beacon_block(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_BEACON_BLOCK_SERVICE_PUBLISH_BEACON_BLOCK, move |ctx, req, resp| {
        instance.publish_beacon_block(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_BEACON_BLOCK_SERVICE_VALIDATOR_ASSIGNMENT, move |ctx, req, resp| {
        instance.validator_assignment(ctx, req, resp)
    });
    builder.build()
}
