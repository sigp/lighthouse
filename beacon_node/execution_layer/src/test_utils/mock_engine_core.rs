use types::{EthSpec, ExecutionPayload, ExecutionRequests, ForkName};
use crate::{BlobsBundle, PayloadStatusV1};
use crate::engine_api::{PayloadAttributes, PayloadId, PayloadStatusV1Status};
use crate::engines::ForkchoiceState;
use crate::json_structures::{JsonForkchoiceUpdatedV1Response, JsonPayloadStatusV1};
use crate::test_utils::handle_rpc::{GENERIC_ERROR_CODE, UNKNOWN_PAYLOAD_ERROR_CODE};

use super::Context;

pub(crate) struct CorePayload<E: EthSpec> {
    pub payload: ExecutionPayload<E>,
    pub blobs: Option<BlobsBundle<E>>,
    pub requests: Option<ExecutionRequests<E>>,
    pub fork: ForkName,
}


impl<E: EthSpec> Context<E> {
    pub(crate) fn core_new_payload(&self, payload: ExecutionPayload<E>) -> Result<PayloadStatusV1, (String, i64)> {
        // Canned responses set by block hash take priority.
            if let Some(status) = self.get_new_payload_status(&payload.block_hash()) {
                return status
                    .map_err(|message| (message, GENERIC_ERROR_CODE));
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
                Some(
                    self.execution_block_generator
                        .write()
                        .new_payload(payload.try_into().unwrap()),
                )
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
