use super::Context;
use crate::engine_api::{http::*, *};
use crate::json_structures::*;
use crate::test_utils::DEFAULT_CLIENT_VERSION;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use tracing::debug;

pub const GENERIC_ERROR_CODE: i64 = -1234;
pub const BAD_PARAMS_ERROR_CODE: i64 = -32602;
pub const UNKNOWN_PAYLOAD_ERROR_CODE: i64 = -38001;
pub const FORK_REQUEST_MISMATCH_ERROR_CODE: i64 = -32000;

pub async fn handle_rpc<E: EthSpec>(
    body: JsonValue,
    ctx: Arc<Context<E>>,
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

    debug!(method, "Mock execution engine");

    match method {
        ETH_SYNCING => ctx
            .syncing_response
            .lock()
            .clone()
            .map(JsonValue::Bool)
            .map_err(|message| (message, GENERIC_ERROR_CODE)),
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
                "0x0" => Ok(serde_json::to_value(
                    ctx.execution_block_generator
                        .read()
                        .genesis_execution_block(),
                )
                .unwrap()),
                other => Err((
                    format!("The tag {} is not supported", other),
                    BAD_PARAMS_ERROR_CODE,
                )),
            }
        }
        ENGINE_NEW_PAYLOAD_V1
        | ENGINE_NEW_PAYLOAD_V2
        | ENGINE_NEW_PAYLOAD_V3
        | ENGINE_NEW_PAYLOAD_V4
        | ENGINE_NEW_PAYLOAD_V5 => {
            let request = match method {
                ENGINE_NEW_PAYLOAD_V1 => JsonExecutionPayload::Bellatrix(
                    get_param::<JsonExecutionPayloadBellatrix<E>>(params, 0)
                        .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?,
                ),
                ENGINE_NEW_PAYLOAD_V2 => get_param::<JsonExecutionPayloadCapella<E>>(params, 0)
                    .map(|jep| JsonExecutionPayload::Capella(jep))
                    .or_else(|_| {
                        get_param::<JsonExecutionPayloadBellatrix<E>>(params, 0)
                            .map(|jep| JsonExecutionPayload::Bellatrix(jep))
                    })
                    .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?,
                ENGINE_NEW_PAYLOAD_V3 => get_param::<JsonExecutionPayloadDeneb<E>>(params, 0)
                    .map(|jep| JsonExecutionPayload::Deneb(jep))
                    .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?,
                ENGINE_NEW_PAYLOAD_V4 => get_param::<JsonExecutionPayloadFulu<E>>(params, 0)
                    .map(|jep| JsonExecutionPayload::Fulu(jep))
                    .or_else(|_| {
                        get_param::<JsonExecutionPayloadElectra<E>>(params, 0)
                            .map(|jep| JsonExecutionPayload::Electra(jep))
                    })
                    .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?,
                ENGINE_NEW_PAYLOAD_V5 => {
                    // TODO(heze):impl heze variant (probably new payload v6?)
                    get_param::<JsonExecutionPayloadGloas<E>>(params, 0)
                        .map(|jep| JsonExecutionPayload::Gloas(jep))
                        .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?
                }
                _ => unreachable!(),
            };

            let fork = ctx
                .execution_block_generator
                .read()
                .get_fork_at_timestamp(*request.timestamp());
            // validate method called correctly according to fork time
            match fork {
                ForkName::Bellatrix => {
                    if matches!(request, JsonExecutionPayload::Capella(_)) {
                        return Err((
                            format!(
                                "{} called with `ExecutionPayloadCapella` before Capella fork!",
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
                    if matches!(request, JsonExecutionPayload::Bellatrix(_)) {
                        return Err((
                            format!(
                                "{} called with `ExecutionPayloadBellatrix` after Capella fork!",
                                method
                            ),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                }
                ForkName::Deneb => {
                    if method == ENGINE_NEW_PAYLOAD_V1 || method == ENGINE_NEW_PAYLOAD_V2 {
                        return Err((
                            format!("{} called after Deneb fork!", method),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                    if matches!(request, JsonExecutionPayload::Bellatrix(_)) {
                        return Err((
                            format!(
                                "{} called with `ExecutionPayloadV1` after Deneb fork!",
                                method
                            ),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                    if matches!(request, JsonExecutionPayload::Capella(_)) {
                        return Err((
                            format!(
                                "{} called with `ExecutionPayloadV2` after Deneb fork!",
                                method
                            ),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                }
                ForkName::Electra | ForkName::Fulu => {
                    if method == ENGINE_NEW_PAYLOAD_V1
                        || method == ENGINE_NEW_PAYLOAD_V2
                        || method == ENGINE_NEW_PAYLOAD_V3
                    {
                        return Err((
                            format!("{} called after Electra fork!", method),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                    if matches!(request, JsonExecutionPayload::Bellatrix(_)) {
                        return Err((
                            format!(
                                "{} called with `ExecutionPayloadBellatrix after Electra fork!",
                                method
                            ),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                    if matches!(request, JsonExecutionPayload::Capella(_)) {
                        return Err((
                            format!(
                                "{} called with `ExecutionPayloadCapella` after Electra fork!",
                                method
                            ),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                    if matches!(request, JsonExecutionPayload::Deneb(_)) {
                        return Err((
                            format!(
                                "{} called with `ExecutionPayloadDeneb` after Electra fork!",
                                method
                            ),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                }
                ForkName::Gloas => {
                    if method != ENGINE_NEW_PAYLOAD_V5 {
                        return Err((
                            format!("{} called after Gloas fork!", method),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                }
                ForkName::Heze => {
                    if method != ENGINE_NEW_PAYLOAD_V5 {
                        return Err((
                            format!("{} called after Heze fork!", method),
                            GENERIC_ERROR_CODE,
                        ));
                    }
                }
                _ => unreachable!(),
            };

            let status = ctx.core_new_payload(request.try_into().unwrap())?;

            Ok(serde_json::to_value(JsonPayloadStatusV1::from(status)).unwrap())
        }
        ENGINE_GET_PAYLOAD_V1
        | ENGINE_GET_PAYLOAD_V2
        | ENGINE_GET_PAYLOAD_V3
        | ENGINE_GET_PAYLOAD_V4
        | ENGINE_GET_PAYLOAD_V5
        | ENGINE_GET_PAYLOAD_V6 => {
            let request: JsonPayloadIdRequest =
                get_param(params, 0).map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?;
            let id = request.into();

            let core = ctx.core_get_payload(id)?;
            let fork = core.fork;

            // validate method called correctly according to shanghai fork time
            if fork == ForkName::Capella && method == ENGINE_GET_PAYLOAD_V1 {
                return Err((
                    format!("{} called after Capella fork!", method),
                    FORK_REQUEST_MISMATCH_ERROR_CODE,
                ));
            }
            // validate method called correctly according to cancun fork time
            if fork == ForkName::Deneb
                && (method == ENGINE_GET_PAYLOAD_V1 || method == ENGINE_GET_PAYLOAD_V2)
            {
                return Err((
                    format!("{} called after Deneb fork!", method),
                    FORK_REQUEST_MISMATCH_ERROR_CODE,
                ));
            }
            // validate method called correctly according to prague fork time
            if fork == ForkName::Electra
                && (method == ENGINE_GET_PAYLOAD_V1
                    || method == ENGINE_GET_PAYLOAD_V2
                    || method == ENGINE_GET_PAYLOAD_V3)
            {
                return Err((
                    format!("{} called after Electra fork!", method),
                    FORK_REQUEST_MISMATCH_ERROR_CODE,
                ));
            }

            // validate method called correctly according to osaka fork time
            if fork == ForkName::Fulu
                && (method == ENGINE_GET_PAYLOAD_V1
                    || method == ENGINE_GET_PAYLOAD_V2
                    || method == ENGINE_GET_PAYLOAD_V3
                    || method == ENGINE_GET_PAYLOAD_V4)
            {
                return Err((
                    format!("{} called after Fulu fork!", method),
                    FORK_REQUEST_MISMATCH_ERROR_CODE,
                ));
            }

            // validate method called correctly according to amsterdam fork time
            if fork == ForkName::Gloas
                && (method == ENGINE_GET_PAYLOAD_V1
                    || method == ENGINE_GET_PAYLOAD_V2
                    || method == ENGINE_GET_PAYLOAD_V3
                    || method == ENGINE_GET_PAYLOAD_V4
                    || method == ENGINE_GET_PAYLOAD_V5)
            {
                return Err((
                    format!("{} called after Gloas fork!", method),
                    FORK_REQUEST_MISMATCH_ERROR_CODE,
                ));
            }

            // validate method called correctly according to heze fork time
            if fork == ForkName::Heze
                && (method == ENGINE_GET_PAYLOAD_V1
                    || method == ENGINE_GET_PAYLOAD_V2
                    || method == ENGINE_GET_PAYLOAD_V3
                    || method == ENGINE_GET_PAYLOAD_V4
                    || method == ENGINE_GET_PAYLOAD_V5)
            {
                return Err((
                    format!("{} called after Heze fork!", method),
                    FORK_REQUEST_MISMATCH_ERROR_CODE,
                ));
            }

            match method {
                ENGINE_GET_PAYLOAD_V1 => Ok(serde_json::to_value(
                    JsonExecutionPayload::try_from(core.payload).unwrap(),
                )
                .unwrap()),
                // V2 onwards wraps the payload in a getPayload response; the version is validated
                // against the fork above, so the shared conversion yields the matching variant.
                _ => {
                    let response =
                        JsonGetPayloadResponse::try_from(core.into_get_payload_response())
                            .map_err(|e| (format!("{e:?}"), GENERIC_ERROR_CODE))?;
                    Ok(serde_json::to_value(response).unwrap())
                }
            }
        }
        ENGINE_GET_BLOBS_V2 => {
            let versioned_hashes =
                get_param::<Vec<Hash256>>(params, 0).map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?;
            let generator = ctx.execution_block_generator.read();
            // V2: all-or-nothing — null if any blob is missing.
            let results: Vec<Option<BlobAndProofV2<E>>> = versioned_hashes
                .iter()
                .map(|hash| match generator.get_blob_and_proof(hash) {
                    Some(BlobAndProof::V2(v2)) => Some(v2),
                    _ => None,
                })
                .collect();
            let response: Option<Vec<BlobAndProofV2<E>>> = results.into_iter().collect();
            Ok(serde_json::to_value(response).unwrap())
        }
        ENGINE_GET_INCLUSION_LIST_V1 => {
            let transactions = ctx.execution_block_generator.read().get_inclusion_list();

            Ok(serde_json::to_value(JsonInclusionListV1(transactions)).unwrap())
        }
        ENGINE_FORKCHOICE_UPDATED_V1
        | ENGINE_FORKCHOICE_UPDATED_V2
        | ENGINE_FORKCHOICE_UPDATED_V3
        | ENGINE_FORKCHOICE_UPDATED_V4 => {
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
                                    ForkName::Bellatrix => {
                                        get_param::<Option<JsonPayloadAttributesV1>>(params, 1)
                                            .map(|opt| opt.map(JsonPayloadAttributes::V1))
                                            .transpose()
                                    }
                                    ForkName::Capella
                                    | ForkName::Deneb
                                    | ForkName::Electra
                                    | ForkName::Fulu
                                    | ForkName::Gloas => {
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
                ENGINE_FORKCHOICE_UPDATED_V3 => {
                    get_param::<Option<JsonPayloadAttributesV3>>(params, 1)
                        .map(|opt| opt.map(JsonPayloadAttributes::V3))
                        .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?
                }
                ENGINE_FORKCHOICE_UPDATED_V4 => {
                    get_param::<Option<JsonPayloadAttributesV4>>(params, 1)
                        .map(|opt| opt.map(JsonPayloadAttributes::V4))
                        .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?
                }
                _ => unreachable!(),
            };

            debug!(
                ?payload_attributes,
                ?forkchoice_state,
                "ENGINE_FORKCHOICE_UPDATED"
            );

            // validate method called correctly according to fork time
            if let Some(pa) = payload_attributes.as_ref() {
                match ctx
                    .execution_block_generator
                    .read()
                    .get_fork_at_timestamp(*pa.timestamp())
                {
                    ForkName::Bellatrix => {
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
                        if method == ENGINE_FORKCHOICE_UPDATED_V3 {
                            return Err((
                                format!(
                                    "{} called with `JsonPayloadAttributesV3` before Deneb fork!",
                                    method
                                ),
                                GENERIC_ERROR_CODE,
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
                    ForkName::Deneb | ForkName::Electra | ForkName::Fulu => {
                        if method == ENGINE_FORKCHOICE_UPDATED_V1 {
                            return Err((
                                format!("{} called after Deneb fork!", method),
                                FORK_REQUEST_MISMATCH_ERROR_CODE,
                            ));
                        }
                        if method == ENGINE_FORKCHOICE_UPDATED_V2 {
                            return Err((
                                format!("{} called after Deneb fork!", method),
                                FORK_REQUEST_MISMATCH_ERROR_CODE,
                            ));
                        }
                    }
                    ForkName::Gloas => {
                        if method != ENGINE_FORKCHOICE_UPDATED_V4 {
                            return Err((
                                format!("{} called after Gloas fork! Use V4.", method),
                                FORK_REQUEST_MISMATCH_ERROR_CODE,
                            ));
                        }
                    }
                    ForkName::Heze => {
                        if method != ENGINE_FORKCHOICE_UPDATED_V4 {
                            return Err((
                                format!("{} called after Heze fork! Use V4.", method),
                                FORK_REQUEST_MISMATCH_ERROR_CODE,
                            ));
                        }
                    }
                    _ => unreachable!(),
                };
            }

            let response = ctx.core_forkchoice_updated(
                forkchoice_state.into(),
                payload_attributes.map(|json| json.into()),
            )?;

            Ok(serde_json::to_value(response).unwrap())
        }
        ENGINE_EXCHANGE_CAPABILITIES => {
            let engine_capabilities = ctx.engine_capabilities.read();
            Ok(serde_json::to_value(engine_capabilities.to_response()).unwrap())
        }
        ENGINE_GET_CLIENT_VERSION_V1 => {
            Ok(serde_json::to_value([DEFAULT_CLIENT_VERSION.clone()]).unwrap())
        }
        ENGINE_GET_PAYLOAD_BODIES_BY_HASH_V1 => {
            let block_hashes = get_param::<Vec<ExecutionBlockHash>>(params, 0)
                .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?;

            let mut response = vec![];
            for block_hash in block_hashes {
                let maybe_payload = ctx
                    .execution_block_generator
                    .read()
                    .execution_payload_by_hash(block_hash);

                match maybe_payload {
                    Some(payload) => {
                        let payload_body: ExecutionPayloadBodyV1<E> = ExecutionPayloadBodyV1 {
                            transactions: payload
                                .transactions()
                                .iter()
                                .map(|tx| {
                                    types::Transaction::<E::MaxBytesPerTransaction>::new(
                                        tx.to_vec(),
                                    )
                                })
                                .collect::<Result<Vec<_>, _>>()
                                .and_then(ssz_types::VariableList::new)
                                .unwrap(),
                            withdrawals: payload
                                .withdrawals()
                                .ok()
                                .map(|withdrawals| {
                                    ssz_types::VariableList::new(withdrawals.to_vec())
                                })
                                .transpose()
                                .unwrap(),
                        };
                        let json_payload_body: JsonExecutionPayloadBodyV1<E> =
                            payload_body.try_into().unwrap();
                        response.push(Some(json_payload_body));
                    }
                    None => response.push(None),
                }
            }

            Ok(serde_json::to_value(response).unwrap())
        }
        ENGINE_GET_PAYLOAD_BODIES_BY_RANGE_V1 => {
            #[derive(Deserialize)]
            #[serde(transparent)]
            struct Quantity(#[serde(with = "serde_utils::u64_hex_be")] pub u64);

            let start = get_param::<Quantity>(params, 0)
                .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?
                .0;
            let count = get_param::<Quantity>(params, 1)
                .map_err(|s| (s, BAD_PARAMS_ERROR_CODE))?
                .0;

            let mut response = vec![];
            for block_num in start..(start + count) {
                let maybe_payload = ctx
                    .execution_block_generator
                    .read()
                    .execution_payload_by_number(block_num);

                match maybe_payload {
                    Some(payload) => {
                        let payload_body: ExecutionPayloadBodyV1<E> = ExecutionPayloadBodyV1 {
                            transactions: payload
                                .transactions()
                                .iter()
                                .map(|tx| {
                                    types::Transaction::<E::MaxBytesPerTransaction>::new(
                                        tx.to_vec(),
                                    )
                                })
                                .collect::<Result<Vec<_>, _>>()
                                .and_then(ssz_types::VariableList::new)
                                .unwrap(),
                            withdrawals: payload
                                .withdrawals()
                                .ok()
                                .map(|withdrawals| {
                                    ssz_types::VariableList::new(withdrawals.to_vec())
                                })
                                .transpose()
                                .unwrap(),
                        };
                        let json_payload_body: JsonExecutionPayloadBodyV1<E> =
                            payload_body.try_into().unwrap();
                        response.push(Some(json_payload_body));
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
