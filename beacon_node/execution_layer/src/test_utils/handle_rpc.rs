use super::Context;
use crate::engine_api::http::*;
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use std::sync::Arc;
use types::EthSpec;

pub async fn handle_rpc<T: EthSpec>(
    body: JsonValue,
    ctx: Arc<Context<T>>,
) -> Result<JsonValue, String> {
    let method = body
        .get("method")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "missing/invalid method field".to_string())?;

    let params = body
        .get("params")
        .ok_or_else(|| "missing/invalid params field".to_string())?;

    match method {
        ETH_SYNCING => Ok(JsonValue::Bool(false)),
        ETH_GET_BLOCK_BY_NUMBER => {
            let tag = params
                .get(0)
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing/invalid params[0] value".to_string())?;

            match tag {
                "latest" => Ok(serde_json::to_value(
                    ctx.execution_block_generator
                        .read()
                        .latest_execution_block(),
                )
                .unwrap()),
                other => Err(format!("The tag {} is not supported", other)),
            }
        }
        ETH_GET_BLOCK_BY_HASH => {
            let hash = params
                .get(0)
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing/invalid params[0] value".to_string())
                .and_then(|s| {
                    s.parse()
                        .map_err(|e| format!("unable to parse hash: {:?}", e))
                })?;

            Ok(serde_json::to_value(
                ctx.execution_block_generator
                    .read()
                    .execution_block_by_hash(hash),
            )
            .unwrap())
        }
        ENGINE_PREPARE_PAYLOAD => {
            let request = get_param_0(params)?;
            let payload_id = ctx
                .execution_block_generator
                .write()
                .prepare_payload(request)?;

            Ok(serde_json::to_value(JsonPayloadIdResponse { payload_id }).unwrap())
        }
        ENGINE_EXECUTE_PAYLOAD => {
            let request: JsonExecutionPayload<T> = get_param_0(params)?;

            let status = ctx
                .static_execute_payload_response
                .lock()
                .unwrap_or_else(|| {
                    ctx.execution_block_generator
                        .write()
                        .execute_payload(request.into())
                });

            Ok(serde_json::to_value(ExecutePayloadResponseWrapper { status }).unwrap())
        }
        ENGINE_GET_PAYLOAD => {
            let request: JsonPayloadIdRequest = get_param_0(params)?;
            let id = request.payload_id;

            let response = ctx
                .execution_block_generator
                .write()
                .get_payload(id)
                .ok_or_else(|| format!("no payload for id {}", id))?;

            Ok(serde_json::to_value(JsonExecutionPayload::from(response)).unwrap())
        }

        ENGINE_CONSENSUS_VALIDATED => {
            let request: JsonConsensusValidatedRequest = get_param_0(params)?;
            ctx.execution_block_generator
                .write()
                .consensus_validated(request.block_hash, request.status)?;

            Ok(JsonValue::Null)
        }
        ENGINE_FORKCHOICE_UPDATED => {
            let request: JsonForkChoiceUpdatedRequest = get_param_0(params)?;
            ctx.execution_block_generator
                .write()
                .forkchoice_updated(request.head_block_hash, request.finalized_block_hash)?;

            Ok(JsonValue::Null)
        }
        other => Err(format!(
            "The method {} does not exist/is not available",
            other
        )),
    }
}

fn get_param_0<T: DeserializeOwned>(params: &JsonValue) -> Result<T, String> {
    params
        .get(0)
        .ok_or_else(|| "missing/invalid params[0] value".to_string())
        .and_then(|param| {
            serde_json::from_value(param.clone())
                .map_err(|e| format!("failed to deserialize param[0]: {:?}", e))
        })
}
