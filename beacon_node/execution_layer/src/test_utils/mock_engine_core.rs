use crate::engine_api::{
    GetPayloadResponse, GetPayloadResponseBellatrix, GetPayloadResponseCapella,
    GetPayloadResponseDeneb, GetPayloadResponseElectra, GetPayloadResponseFulu,
    GetPayloadResponseGloas, GetPayloadResponseHeze, PayloadAttributes, PayloadId, PayloadStatusV1Status,
};
use crate::engines::ForkchoiceState;
use crate::json_structures::{JsonForkchoiceUpdatedV1Response, JsonPayloadStatusV1};
use crate::test_utils::handle_rpc::{GENERIC_ERROR_CODE, UNKNOWN_PAYLOAD_ERROR_CODE};
use crate::{BlobsBundle, PayloadStatusV1};
use types::{
    EthSpec, ExecutionPayload, ExecutionRequests, ExecutionRequestsElectra, ExecutionRequestsGloas,
    ForkName, Uint256,
};

use super::{Context, DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI};

pub(crate) struct CorePayload<E: EthSpec> {
    pub payload: ExecutionPayload<E>,
    pub blobs: Option<BlobsBundle<E>>,
    pub requests: Option<ExecutionRequests<E>>,
    pub fork: ForkName,
}

impl<E: EthSpec> CorePayload<E> {
    pub(crate) fn into_get_payload_response(self) -> GetPayloadResponse<E> {
        let CorePayload {
            payload,
            blobs,
            requests,
            fork: _,
        } = self;
        let block_value = Uint256::from(DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI);
        let blobs_bundle = blobs.unwrap_or_default();

        match payload {
            ExecutionPayload::Bellatrix(execution_payload) => {
                GetPayloadResponse::Bellatrix(GetPayloadResponseBellatrix {
                    execution_payload,
                    block_value,
                })
            }
            ExecutionPayload::Capella(execution_payload) => {
                GetPayloadResponse::Capella(GetPayloadResponseCapella {
                    execution_payload,
                    block_value,
                })
            }
            ExecutionPayload::Deneb(execution_payload) => {
                GetPayloadResponse::Deneb(GetPayloadResponseDeneb {
                    execution_payload,
                    block_value,
                    blobs_bundle,
                    should_override_builder: false,
                })
            }
            ExecutionPayload::Electra(execution_payload) => {
                GetPayloadResponse::Electra(GetPayloadResponseElectra {
                    execution_payload,
                    block_value,
                    blobs_bundle,
                    should_override_builder: false,
                    requests: electra_requests(requests),
                })
            }
            ExecutionPayload::Fulu(execution_payload) => {
                GetPayloadResponse::Fulu(GetPayloadResponseFulu {
                    execution_payload,
                    block_value,
                    blobs_bundle,
                    should_override_builder: false,
                    requests: electra_requests(requests),
                })
            }
            ExecutionPayload::Gloas(execution_payload) => {
                GetPayloadResponse::Gloas(GetPayloadResponseGloas {
                    execution_payload,
                    block_value,
                    blobs_bundle,
                    should_override_builder: false,
                    requests: gloas_requests(requests),
                })
            }
            ExecutionPayload::Heze(execution_payload) => {
                GetPayloadResponse::Heze(GetPayloadResponseHeze {
                    execution_payload,
                    block_value,
                    blobs_bundle,
                    should_override_builder: false,
                    requests: gloas_requests(requests),
                })
            }
        }
    }
}

fn electra_requests<E: EthSpec>(
    requests: Option<ExecutionRequests<E>>,
) -> ExecutionRequestsElectra<E> {
    match requests {
        Some(ExecutionRequests::Electra(inner)) => inner,
        _ => ExecutionRequestsElectra::default(),
    }
}

fn gloas_requests<E: EthSpec>(requests: Option<ExecutionRequests<E>>) -> ExecutionRequestsGloas<E> {
    match requests {
        Some(ExecutionRequests::Gloas(inner)) => inner,
        _ => ExecutionRequestsGloas::default(),
    }
}

impl<E: EthSpec> Context<E> {
    pub(crate) fn core_new_payload(
        &self,
        payload: ExecutionPayload<E>,
    ) -> Result<PayloadStatusV1, (String, i64)> {
        // Canned responses set by block hash take priority.
        if let Some(status) = self.get_new_payload_status(&payload.block_hash()) {
            return status.map_err(|message| (message, GENERIC_ERROR_CODE));
        }

        let (static_response, should_import) =
            if let Some(mut response) = self.static_new_payload_response.lock().clone() {
                if response.status.status == PayloadStatusV1Status::Valid {
                    response.status.latest_valid_hash = Some(payload.block_hash())
                }

                (Some(response.status), response.should_import)
            } else {
                (None, true)
            };

        let dynamic_response = if should_import {
            Some(self.execution_block_generator.write().new_payload(payload))
        } else {
            None
        };

        Ok(static_response.or(dynamic_response).unwrap())
    }

    pub(crate) fn core_forkchoice_updated(
        &self,
        state: ForkchoiceState,
        attrs: Option<PayloadAttributes>,
    ) -> Result<JsonForkchoiceUpdatedV1Response, (String, i64)> {
        *self.previous_forkchoice_request.lock() = Some((state, attrs.clone()));

        if let Some(hook_response) = self.hook.lock().on_forkchoice_updated(state, attrs.clone()) {
            return Ok(hook_response);
        }

        let head_block_hash = state.head_block_hash;

        // Canned responses set by block hash take priority.
        if let Some(status) = self.get_fcu_payload_status(&head_block_hash) {
            return status
                .map(|status| JsonForkchoiceUpdatedV1Response {
                    payload_status: JsonPayloadStatusV1::from(status),
                    payload_id: None,
                })
                .map_err(|message| (message, GENERIC_ERROR_CODE));
        }

        let mut response = self
            .execution_block_generator
            .write()
            .forkchoice_updated(state, attrs)
            .map_err(|s| (s, GENERIC_ERROR_CODE))?;

        if let Some(mut status) = self.static_forkchoice_updated_response.lock().clone() {
            if status.status == PayloadStatusV1Status::Valid {
                status.latest_valid_hash = Some(head_block_hash);
            }

            response.payload_status = status.into();
        }

        Ok(response)
    }

    pub(crate) fn core_get_payload(&self, id: PayloadId) -> Result<CorePayload<E>, (String, i64)> {
        let payload = self
            .execution_block_generator
            .write()
            .get_payload(&id)
            .ok_or_else(|| {
                (
                    format!("no payload for id {:?}", id),
                    UNKNOWN_PAYLOAD_ERROR_CODE,
                )
            })?;

        let blobs = self.execution_block_generator.write().get_blobs_bundle(&id);
        let requests = self
            .execution_block_generator
            .read()
            .get_execution_requests(&id);

        let fork = self
            .execution_block_generator
            .read()
            .get_fork_at_timestamp(payload.timestamp());

        Ok(CorePayload {
            payload,
            blobs,
            requests,
            fork,
        })
    }
}
