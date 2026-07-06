//! The Engine API transport seam: dispatch between JSON-RPC and the optional REST-SSZ client.

use crate::engine_api::{
    BlockByNumberQuery, EngineCapabilities, Error as EngineApiError, ExecutionBlock,
    ExecutionPayloadBodyV1, ForkchoiceUpdatedResponse, GetPayloadResponse, NewPayloadRequest,
    PayloadAttributes, PayloadId, PayloadStatusV1,
};
use crate::engines::ForkchoiceState;
use crate::json_structures::{BlobAndProofV2, BlobAndProofV3};
use crate::rest::HttpRestSsz;
use crate::{ClientVersionV1, HttpJsonRpc};
use std::sync::OnceLock;
use std::time::Duration;
use types::{EthSpec, ExecutionBlockHash, ForkName, Hash256};

/// Resolved `engine_*` transport. Only set when `rest` is `Some`; `eth_*` always use JSON-RPC.
pub enum Transport {
    Rest,
    JsonRpcOnly,
}

/// Mandatory JSON-RPC plus optional, opt-in REST-SSZ. `engine_*` dispatch to `rest` once
/// `decision` is `Rest`; `eth_*` always use `json_rpc`.
pub struct EngineApi {
    json_rpc: HttpJsonRpc,
    rest: Option<HttpRestSsz>,
    decision: OnceLock<Transport>,
}

impl EngineApi {
    pub fn new(json_rpc: HttpJsonRpc, rest: Option<HttpRestSsz>) -> Self {
        Self {
            json_rpc,
            rest,
            decision: OnceLock::new(),
        }
    }

    /// The REST client iff it is the resolved transport. `decision` is only ever set to `Rest`
    /// when `rest` is `Some`, so `Rest` implies a client is present.
    fn active_rest(&self) -> Option<&HttpRestSsz> {
        match self.decision.get() {
            Some(Transport::Rest) => self.rest.as_ref(),
            _ => None,
        }
    }

    pub async fn new_payload<E: EthSpec>(
        &self,
        new_payload_request: NewPayloadRequest<'_, E>,
    ) -> Result<PayloadStatusV1, EngineApiError> {
        self.json_rpc.new_payload(new_payload_request).await
    }

    pub async fn get_payload<E: EthSpec>(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<E>, EngineApiError> {
        self.json_rpc.get_payload(fork_name, payload_id).await
    }

    pub async fn forkchoice_updated(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
    ) -> Result<ForkchoiceUpdatedResponse, EngineApiError> {
        self.json_rpc
            .forkchoice_updated(forkchoice_state, payload_attributes)
            .await
    }

    pub async fn get_payload_bodies_by_hash_v1<E: EthSpec>(
        &self,
        block_hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, EngineApiError> {
        self.json_rpc
            .get_payload_bodies_by_hash_v1(block_hashes)
            .await
    }

    pub async fn get_payload_bodies_by_range_v1<E: EthSpec>(
        &self,
        start: u64,
        count: u64,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, EngineApiError> {
        self.json_rpc
            .get_payload_bodies_by_range_v1(start, count)
            .await
    }

    pub async fn get_blobs_v2<E: EthSpec>(
        &self,
        versioned_hashes: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV2<E>>>, EngineApiError> {
        self.json_rpc.get_blobs_v2(versioned_hashes).await
    }

    pub async fn get_blobs_v3<E: EthSpec>(
        &self,
        versioned_hashes: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV3<E>>>, EngineApiError> {
        self.json_rpc.get_blobs_v3(versioned_hashes).await
    }

    pub async fn get_engine_capabilities(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<EngineCapabilities, EngineApiError> {
        self.json_rpc.get_engine_capabilities(age_limit).await
    }

    pub async fn get_engine_version(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<Vec<ClientVersionV1>, EngineApiError> {
        self.json_rpc.get_engine_version(age_limit).await
    }

    pub async fn upcheck(&self) -> Result<(), EngineApiError> {
        self.json_rpc.upcheck().await
    }

    pub async fn get_block_by_number(
        &self,
        query: BlockByNumberQuery<'_>,
    ) -> Result<Option<ExecutionBlock>, EngineApiError> {
        self.json_rpc.get_block_by_number(query).await
    }

    pub async fn clear_exchange_capabilties_cache(&self) {
        match self.active_rest() {
            Some(rest) => rest.clear_ssz_capabilities_cache().await,
            None => self.json_rpc.clear_exchange_capabilties_cache().await,
        }
    }

    pub async fn clear_engine_version_cache(&self) {
        match self.active_rest() {
            Some(rest) => rest.clear_engine_version_cache().await,
            None => self.json_rpc.clear_engine_version_cache().await,
        }
    }
}
