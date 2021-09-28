use super::Context;
use crate::engine_api::http::*;
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
                    ctx.execution_block_generator.read().await.latest_block(),
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
                    .await
                    .block_by_hash(hash),
            )
            .unwrap())
        }
        ENGINE_CONSENSUS_VALIDATED => Ok(JsonValue::Null),
        ENGINE_FORKCHOICE_UPDATED => Ok(JsonValue::Null),
        other => Err(format!(
            "The method {} does not exist/is not available",
            other
        )),
    }
}
