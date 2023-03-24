use super::Context;
use crate::engine_api::{http::*, *};
use crate::json_structures::*;
use crate::test_utils::DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use types::{EthSpec, ForkName};

pub const GENERIC_ERROR_CODE: i64 = -1234;
pub const BAD_PARAMS_ERROR_CODE: i64 = -32602;
pub const UNKNOWN_PAYLOAD_ERROR_CODE: i64 = -38001;
pub const FORK_REQUEST_MISMATCH_ERROR_CODE: i64 = -32000;

pub async fn handle_rpc<T: EthSpec>(
    body: JsonValue,
    ctx: Arc<Context<T>>,
) -> Result<JsonValue, (String, i64)> {
    *ctx.previous_request.lock() = Some(body.clone());

    let method = body
        .get("method")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "missing/invalid method field".to_string())
        .map_err(|s| (s, GENERIC_ERROR_CODE))?;

    let params = body
        .get("params")
        .ok_or_else(|| "missing/invalid params field".to_string())
        .map_err(|s| (s, GENERIC_ERROR_CODE))?;

    match method {
        ETH_SYNCING => Ok(JsonValue::Bool(false)),
        ETH_GET_BLOCK_BY_NUMBER => {
            let tag = params
                .get(0)
                .and_then(JsonValue::as_str)
                .ok_or_else(|| "missing/invalid params[0] value".to_string())
                .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?;

            match tag {
                "latest" => Ok(serde_json::to_value(
                    ctx.execution_block_generator
                        .read()
                        .latest_execution_block(),
                )
                .unwrap()),
                other => Err((
                    format!("The tag {} is not supported", other),
                    BAD_PARAMS_ERROR_CODE,
                )),
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
                })
                .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?;

            // If we have a static response set, just return that.
            if let Some(response) = *ctx.static_get_block_by_hash_response.lock() {
                return Ok(serde_json::to_value(response).unwrap());
            }

            let full_tx = params
                .get(1)
                .and_then(JsonValue::as_bool)
                .ok_or_else(|| "missing/invalid params[1] value".to_string())
                .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?;
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
        ENGINE_NEW_PAYLOAD_V1 | ENGINE_NEW_PAYLOAD_V2 => {
            let request = match method {
                ENGINE_NEW_PAYLOAD_V1 => JsonExecutionPayload::V1(
                    get_param::<JsonExecutionPayloadV1<T>>(params, 0)
                        .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?,
                ),
                ENGINE_NEW_PAYLOAD_V2 => get_param::<JsonExecutionPayloadV2<T>>(params, 0)
                    .map(|jep| JsonExecutionPayload::V2(jep))
                    .or_else(|_| {
                        get_param::<JsonExecutionPayloadV1<T>>(params, 0)
                            .map(|jep| JsonExecutionPayload::V1(jep))
                    })
                    .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?,
                // TODO(4844) add that here..
                _ => unreachable!(),
            };

            let fork = ctx
                .execution_block_generator
                .read()
                .get_fork_at_timestamp(*request.timestamp());
            // validate method called correctly according to shanghai fork time
            match fork {
                ForkName::Merge => {
                    if matches!(request, JsonExecutionPayload::V2(_)) {
                        return Err((
                            format!(
                                "{} called with `ExecutionPayloadV2` before Capella fork!",
                                method
                            ),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                }
                ForkName::Capella => {
                    if method == ENGINE_NEW_PAYLOAD_V1 {
                        return Err((
                            format!("{} called after Capella fork!", method),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                    if matches!(request, JsonExecutionPayload::V1(_)) {
                        return Err((
                            format!(
                                "{} called with `ExecutionPayloadV1` after Capella fork!",
                                method
                            ),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                }
                // TODO(4844) add 4844 error checking here
                _ => unreachable!(),
            };

            // Canned responses set by block hash take priority.
            if let Some(status) = ctx.get_new_payload_status(request.block_hash()) {
                return Ok(serde_json::to_value(JsonPayloadStatusV1::from(status)).unwrap());
            }

            let (static_response, should_import) =
                if let Some(mut response) = ctx.static_new_payload_response.lock().clone() {
                    if response.status.status == PayloadStatusV1Status::Valid {
                        response.status.latest_valid_hash = Some(*request.block_hash())
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
        ENGINE_GET_PAYLOAD_V1 | ENGINE_GET_PAYLOAD_V2 => {
            let request: JsonPayloadIdRequest =
                get_param(params, 0).map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?;
            let id = request.into();

            let response = ctx
                .execution_block_generator
                .write()
                .get_payload(&id)
                .ok_or_else(|| {
                    (
                        format!("no payload for id {:?}", id),
                        UNKNOWN_PAYLOAD_ERROR_CODE,
                    )
                })?;

            // validate method called correctly according to shanghai fork time
            if ctx
                .execution_block_generator
                .read()
                .get_fork_at_timestamp(response.timestamp())
                == ForkName::Capella
                && method == ENGINE_GET_PAYLOAD_V1
            {
                return Err((
                    format!("{} called after Capella fork!", method),
                    FORK_REQUEST_MISMATCH_ERROR_CODE,
                ));
            }
            // TODO(4844) add 4844 error checking here

            match method {
                ENGINE_GET_PAYLOAD_V1 => {
                    Ok(serde_json::to_value(JsonExecutionPayload::from(response)).unwrap())
                }
                ENGINE_GET_PAYLOAD_V2 => Ok(match JsonExecutionPayload::from(response) {
                    JsonExecutionPayload::V1(execution_payload) => {
                        serde_json::to_value(JsonGetPayloadResponseV1 {
                            execution_payload,
                            block_value: DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI.into(),
                        })
                        .unwrap()
                    }
                    JsonExecutionPayload::V2(execution_payload) => {
                        serde_json::to_value(JsonGetPayloadResponseV2 {
                            execution_payload,
                            block_value: DEFAULT_MOCK_EL_PAYLOAD_VALUE_WEI.into(),
                        })
                        .unwrap()
                    }
                }),
                _ => unreachable!(),
            }
        }
        ENGINE_FORKCHOICE_UPDATED_V1 | ENGINE_FORKCHOICE_UPDATED_V2 => {
            let forkchoice_state: JsonForkchoiceStateV1 =
                get_param(params, 0).map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?;
            let payload_attributes = match method {
                ENGINE_FORKCHOICE_UPDATED_V1 => {
                    let jpa1: Option<JsonPayloadAttributesV1> =
                        get_param(params, 1).map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?;
                    jpa1.map(JsonPayloadAttributes::V1)
                }
                ENGINE_FORKCHOICE_UPDATED_V2 => {
                    // we can't use `deny_unknown_fields` without breaking compatibility with some
                    // clients that haven't updated to the latest engine_api spec. So instead we'll
                    // need to deserialize based on timestamp
                    get_param::<Option<JsonPayloadAttributes>>(params, 1)
                        .and_then(|pa| {
                            pa.and_then(|pa| {
                                match ctx
                                    .execution_block_generator
                                    .read()
                                    .get_fork_at_timestamp(*pa.timestamp())
                                {
                                    ForkName::Merge => {
                                        get_param::<Option<JsonPayloadAttributesV1>>(params, 1)
                                            .map(|opt| opt.map(JsonPayloadAttributes::V1))
                                            .transpose()
                                    }
                                    ForkName::Capella => {
                                        get_param::<Option<JsonPayloadAttributesV2>>(params, 1)
                                            .map(|opt| opt.map(JsonPayloadAttributes::V2))
                                            .transpose()
                                    }
                                    _ => unreachable!(),
                                }
                            })
                            .transpose()
                        })
                        .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?
                }
                _ => unreachable!(),
            };

            // validate method called correctly according to shanghai fork time
            if let Some(pa) = payload_attributes.as_ref() {
                match ctx
                    .execution_block_generator
                    .read()
                    .get_fork_at_timestamp(*pa.timestamp())
                {
                    ForkName::Merge => {
                        if matches!(pa, JsonPayloadAttributes::V2(_)) {
                            return Err((
                                format!(
                                    "{} called with `JsonPayloadAttributesV2` before Capella fork!",
                                    method
                                ),
                                GENERIC_ERROR_CODE,
                            ));
                        }
                    }
                    ForkName::Capella => {
                        if method == ENGINE_FORKCHOICE_UPDATED_V1 {
                            return Err((
                                format!("{} called after Capella fork!", method),
                                FORK_REQUEST_MISMATCH_ERROR_CODE,
                            ));
                        }
                        if matches!(pa, JsonPayloadAttributes::V1(_)) {
                            return Err((
                                format!(
                                    "{} called with `JsonPayloadAttributesV1` after Capella fork!",
                                    method
                                ),
                                FORK_REQUEST_MISMATCH_ERROR_CODE,
                            ));
                        }
                    }
                    // TODO(4844) add 4844 error checking here
                    _ => unreachable!(),
                };
            }

            if let Some(hook_response) = ctx
                .hook
                .lock()
                .on_forkchoice_updated(forkchoice_state.clone(), payload_attributes.clone())
            {
                return Ok(serde_json::to_value(hook_response).unwrap());
            }

            let head_block_hash = forkchoice_state.head_block_hash;

            // Canned responses set by block hash take priority.
            if let Some(status) = ctx.get_fcu_payload_status(&head_block_hash) {
                let response = JsonForkchoiceUpdatedV1Response {
                    payload_status: JsonPayloadStatusV1::from(status),
                    payload_id: None,
                };
                return Ok(serde_json::to_value(response).unwrap());
            }

            let mut response = ctx
                .execution_block_generator
                .write()
                .forkchoice_updated(
                    forkchoice_state.into(),
                    payload_attributes.map(|json| json.into()),
                )
                .map_err(|s| (s, GENERIC_ERROR_CODE))?;

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
        ENGINE_EXCHANGE_CAPABILITIES => {
            let engine_capabilities = ctx.engine_capabilities.read();
            Ok(serde_json::to_value(engine_capabilities.to_response()).unwrap())
        }
        ENGINE_GET_PAYLOAD_BODIES_BY_RANGE_V1 => {
            #[derive(Deserialize)]
            #[serde(transparent)]
            struct Quantity(#[serde(with = "eth2_serde_utils::u64_hex_be")] pub u64);

            let start = get_param::<Quantity>(params, 0)
                .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?
                .0;
            let count = get_param::<Quantity>(params, 1)
                .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?
                .0;

            let mut response = vec![];
            for block_num in start..(start + count) {
                let maybe_block = ctx
                    .execution_block_generator
                    .read()
                    .execution_block_with_txs_by_number(block_num);

                match maybe_block {
                    Some(block) => {
                        let transactions = Transactions::<T>::new(
                            block
                                .transactions()
                                .iter()
                                .map(|transaction| VariableList::new(transaction.rlp().to_vec()))
                                .collect::<Result<_, _>>()
                                .map_err(|e| {
                                    (
                                        format!("failed to deserialize transaction: {:?}", e),
                                        GENERIC_ERROR_CODE,
                                    )
                                })?,
                        )
                        .map_err(|e| {
                            (
                                format!("failed to deserialize transactions: {:?}", e),
                                GENERIC_ERROR_CODE,
                            )
                        })?;

                        response.push(Some(JsonExecutionPayloadBodyV1::<T> {
                            transactions,
                            withdrawals: block
                                .withdrawals()
                                .ok()
                                .map(|withdrawals| VariableList::from(withdrawals.clone())),
                        }));
                    }
                    None => response.push(None),
                }
            }

            Ok(serde_json::to_value(response).unwrap())
        }
        other => Err((
            format!("The method {} does not exist/is not available", other),
            METHOD_NOT_FOUND_CODE,
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
