use super::Context;
use std::sync::Arc;
use types::EthSpec;

pub async fn handle_rpc<T: EthSpec>(
    body: serde_json::Value,
    ctx: Arc<Context<T>>,
) -> Result<serde_json::Value, String> {
    todo!("handle_rpc")
}
