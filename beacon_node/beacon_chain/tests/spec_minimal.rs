// Integration tests that run under the minimal spec preset. Mainnet-preset tests live in
// `main.rs`.
mod envelope_verification;
mod events;
mod op_verification;
mod prepare_payload;
mod rewards;
mod store_tests;
mod tests;
mod unrealized_checkpoints;
