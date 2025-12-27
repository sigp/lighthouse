pub use metrics::*;
use std::sync::LazyLock;

pub static LEAN_PQ_SIGNATURE_ATTESTATION_SIGNING_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "lean_pq_signature_attestation_signing_time_seconds",
            "Time taken to sign an attestation",
        )
    });

pub static LEAN_PQ_SIGNATURE_ATTESTATION_VERIFICATION_TIME: LazyLock<Result<Histogram>> =
    LazyLock::new(|| {
        try_create_histogram(
            "lean_pq_signature_attestation_verification_time_seconds",
            "Time taken to verify an attestation signature",
        )
    });
