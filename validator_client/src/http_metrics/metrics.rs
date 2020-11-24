use super::Context;
use crate::ProductionValidatorClient;
use eth2::lighthouse::Health;
use lazy_static::lazy_static;
use lighthouse_metrics::{Encoder, TextEncoder};
use types::EthSpec;

pub use lighthouse_metrics::*;

pub fn gather_prometheus_metrics<T: EthSpec>(
    ctx: &Context<T>,
) -> std::result::Result<String, String> {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();

    warp_utils::metrics::scrape_health_metrics();

    encoder
        .encode(&lighthouse_metrics::gather(), &mut buffer)
        .unwrap();

    String::from_utf8(buffer).map_err(|e| format!("Failed to encode prometheus info: {:?}", e))
}
