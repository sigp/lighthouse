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
use tokio::sync::Mutex;
use tracing::warn;

/// Resolved `engine_*` transport. Only set when `rest` is `Some`; `eth_*` always use JSON-RPC.
#[derive(Debug)]
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
    fcu_lock: Mutex<()>
}

impl EngineApi {
    pub fn new(json_rpc: HttpJsonRpc, rest: Option<HttpRestSsz>) -> Self {
        Self {
            json_rpc,
            rest,
            decision: OnceLock::new(),
            fcu_lock: Mutex::new(())
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
        match self.active_rest() {
            Some(rest) => rest.new_payload(new_payload_request).await,
            None => self.json_rpc.new_payload(new_payload_request).await,
        }
    }

    pub async fn get_payload<E: EthSpec>(
        &self,
        fork_name: ForkName,
        payload_id: PayloadId,
    ) -> Result<GetPayloadResponse<E>, EngineApiError> {
        match self.active_rest() {
            Some(rest) => rest.get_payload(fork_name, payload_id).await,
            None => self.json_rpc.get_payload(fork_name, payload_id).await,
        }
    }

    pub async fn forkchoice_updated<E: EthSpec>(
        &self,
        forkchoice_state: ForkchoiceState,
        payload_attributes: Option<PayloadAttributes>,
        fork: ForkName
    ) -> Result<ForkchoiceUpdatedResponse, EngineApiError> {
        match self.active_rest() {
            Some(rest) => {
                // At most one POST /forkchoice in flight based on REST-SSZ spec.
                let _fcu_guard = self.fcu_lock.lock().await;
                rest.forkchoice_updated::<E>(fork, forkchoice_state, payload_attributes).await
            },
            None => self.json_rpc.forkchoice_updated(forkchoice_state, payload_attributes).await,
        }
    }

    pub async fn get_payload_bodies_by_hash<E: EthSpec>(
        &self,
        fork: ForkName,
        block_hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, EngineApiError> {
        match self.active_rest() {
            Some(rest) => rest.get_payload_bodies_by_hash::<E>(fork, block_hashes).await,
            None => self.json_rpc.get_payload_bodies_by_hash_v1(block_hashes).await,
        }
    }

    pub async fn get_payload_bodies_by_range<E: EthSpec>(
        &self,
        fork: ForkName,
        start: u64,
        count: u64,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV1<E>>>, EngineApiError> {
        match self.active_rest() {
            Some(rest) => rest.get_payload_bodies_by_range::<E>(fork, start, count).await,
            None => self.json_rpc.get_payload_bodies_by_range_v1(start, count).await,
        }
    }

    pub async fn get_blobs_v2<E: EthSpec>(
        &self,
        versioned_hashes: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV2<E>>>, EngineApiError> {
        match self.active_rest() {
            Some(rest) => rest.get_blobs_v2(versioned_hashes).await,
            None => self.json_rpc.get_blobs_v2(versioned_hashes).await,
        }
    }

    pub async fn get_blobs_v3<E: EthSpec>(
        &self,
        versioned_hashes: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV3<E>>>, EngineApiError> {
        match self.active_rest() {
            Some(rest) => rest.get_blobs_v3(versioned_hashes).await,
            None => self.json_rpc.get_blobs_v3(versioned_hashes).await,
        }
    }

    pub async fn get_engine_capabilities(&self, age_limit: Option<Duration>)
    -> Result<EngineCapabilities, EngineApiError>
    {
        if self.decision.get().is_none() {
            self.resolve_transport(age_limit).await
        }
        else {
            match self.active_rest() {
                Some(rest) => rest.get_engine_capabilities(age_limit).await,
                None => self.json_rpc.get_engine_capabilities(age_limit).await,
            }
        }
    }

    pub async fn get_engine_version(
        &self,
        age_limit: Option<Duration>,
    ) -> Result<Vec<ClientVersionV1>, EngineApiError> {
        match self.active_rest() {
            Some(rest) => rest.get_engine_version(age_limit).await,
            None => self.json_rpc.get_engine_version(age_limit).await,
        }
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

    async fn resolve_transport(&self, age_limit: Option<Duration>) -> Result<EngineCapabilities, EngineApiError> {
        match self.rest.as_ref() {
            Some(rest) => {
                match rest.resolve_http_and_get_capabilities(age_limit).await {
                    Ok(capabilities) => {
                        self.decision.set(Transport::Rest)?;
                        Ok(capabilities)
                    }
                    Err(e) => {
                        // Any probe failure falls back to JSON-RPC for the rest of the process run.
                        warn!(error = ?e, "REST-SSZ capabilities probe failed; falling back to JSON-RPC");
                        let capabilities = self.json_rpc.get_engine_capabilities(age_limit).await?;
                        self.decision.set(Transport::JsonRpcOnly)?;
                        Ok(capabilities)
                    }
                }
            },
            None => {
                let capabilities = self.json_rpc.get_engine_capabilities(age_limit).await?;
                self.decision.set(Transport::JsonRpcOnly)?;
                Ok(capabilities)
            }
        }
    }
}
