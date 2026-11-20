pub use metrics::*;
use std::sync::LazyLock;

pub static PROOF_ENGINE_VERIFICATION_TIMES: LazyLock<Result<HistogramVec>> = LazyLock::new(|| {
    try_create_histogram_vec_with_buckets(
        "proof_engine_verification_times",
        "Duration of proof engine verification calls, per proof type",
        decimal_buckets(-3, 1),
        &["proof_type"],
    )
});
