// Integration tests that run under the mainnet spec preset. Minimal-preset tests live in
// `spec_minimal.rs`.
mod attestation_production;
mod attestation_verification;
mod blob_verification;
mod block_verification;
mod column_verification;
mod payload_invalidation;
mod schema_stability;
mod sync_committee_verification;
mod validator_monitor;
