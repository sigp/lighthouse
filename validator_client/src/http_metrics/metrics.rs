use super::Context;
use std::time::{SystemTime, UNIX_EPOCH};
use types::EthSpec;

lazy_static::lazy_static! {
    pub static ref GENESIS_DISTANCE: Result<Gauge> = try_create_float_gauge(
        "vc_genesis_distance_seconds",
        "Distance between now and genesis time"
    );
}

pub use lighthouse_metrics::*;

pub fn gather_prometheus_metrics<T: EthSpec>(
    ctx: &Context<T>,
) -> std::result::Result<String, String> {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();

    {
        let shared = ctx.shared.read();

        if let Some(genesis_time) = shared.genesis_time {
            if let Some(now) = SystemTime::now().duration_since(UNIX_EPOCH).ok() {
                let distance = now.as_secs() as f64 - genesis_time as f64;
                set_float_gauge(&GENESIS_DISTANCE, distance);
            }
        }
    }

    warp_utils::metrics::scrape_health_metrics();

    encoder
        .encode(&lighthouse_metrics::gather(), &mut buffer)
        .unwrap();

    String::from_utf8(buffer).map_err(|e| format!("Failed to encode prometheus info: {:?}", e))
}
