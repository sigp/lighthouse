use super::Context;
use crate::engine_api::{http::*, *};
use crate::json_structures::*;
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use std::sync::Arc;
use types::EthSpec;

pub async fn handle_rpc<T: EthSpec>(
    body: JsonValue,
    ctx: Arc<Context<T>>,
) -> Result<JsonValue, String> {
    *ctx.previous_request.lock() = Some(body.clone());

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
            let full_tx = params
                .get(1)
                .and_then(JsonValue::as_bool)
                .ok_or_else(|| "missing/invalid params[1] value".to_string())?;
            if full_tx {
                Ok(serde_json::to_value(
                    ctx.execution_block_generator
                        .read()
                        .execution_block_with_txs_by_hash(hash),
                )
                .unwrap())
            } else {
                Ok(serde_json::to_value(
                    ctx.execution_block_generator
                        .read()
                        .execution_block_by_hash(hash),
                )
                .unwrap())
            }
        }
        ENGINE_NEW_PAYLOAD_V1 => {
            let request: JsonExecutionPayloadV1<T> = get_param(params, 0)?;

            let (static_response, should_import) =
                if let Some(mut response) = ctx.static_new_payload_response.lock().clone() {
                    if response.status.status == PayloadStatusV1Status::Valid {
                        response.status.latest_valid_hash = Some(request.block_hash)
                    }

                    (Some(response.status), response.should_import)
                } else {
                    (None, true)
                };

            let dynamic_response = if should_import {
                Some(
                    ctx.execution_block_generator
                        .write()
                        .new_payload(request.into()),
                )
            } else {
                None
            };

            let response = static_response.or(dynamic_response).unwrap();

            Ok(serde_json::to_value(JsonPayloadStatusV1::from(response)).unwrap())
        }
        ENGINE_GET_PAYLOAD_V1 => {
            let request: JsonPayloadIdRequest = get_param(params, 0)?;
            let id = request.into();

            let response = ctx
                .execution_block_generator
                .write()
                .get_payload(&id)
                .ok_or_else(|| format!("no payload for id {:?}", id))?;

            Ok(serde_json::to_value(JsonExecutionPayloadV1::from(response)).unwrap())
        }
        ENGINE_FORKCHOICE_UPDATED_V1 => {
            let forkchoice_state: JsonForkChoiceStateV1 = get_param(params, 0)?;
            let payload_attributes: Option<JsonPayloadAttributesV1> = get_param(params, 1)?;

            let head_block_hash = forkchoice_state.head_block_hash;

            let mut response = ctx
                .execution_block_generator
                .write()
                .forkchoice_updated_v1(
                    forkchoice_state.into(),
                    payload_attributes.map(|json| json.into()),
                )?;

            if let Some(mut status) = ctx.static_forkchoice_updated_response.lock().clone() {
                if status.status == PayloadStatusV1Status::Valid {
                    status.latest_valid_hash = Some(head_block_hash)
                }

                response.payload_status = status.into();
            }

            Ok(serde_json::to_value(response).unwrap())
        }
        ENGINE_EXCHANGE_TRANSITION_CONFIGURATION_V1 => {
            let block_generator = ctx.execution_block_generator.read();
            let transition_config: TransitionConfigurationV1 = TransitionConfigurationV1 {
                terminal_total_difficulty: block_generator.terminal_total_difficulty,
                terminal_block_hash: block_generator.terminal_block_hash,
                terminal_block_number: block_generator.terminal_block_number,
            };
            Ok(serde_json::to_value(transition_config).unwrap())
        }
        other => Err(format!(
            "The method {} does not exist/is not available",
            other
        )),
    }
}

fn get_param<T: DeserializeOwned>(params: &JsonValue, index: usize) -> Result<T, String> {
    params
        .get(index)
        .ok_or_else(|| format!("missing/invalid params[{}] value", index))
        .and_then(|param| {
            serde_json::from_value(param.clone())
                .map_err(|e| format!("failed to deserialize param[{}]: {:?}", index, e))
        })
}
