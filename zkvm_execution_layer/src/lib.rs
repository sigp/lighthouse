pub mod config;

pub mod proof_generation;
pub mod proof_verification;

pub mod registry_proof_gen;
pub mod registry_proof_verification;

pub mod dummy_proof_gen;
pub mod dummy_proof_verifier;

/// Engine API implementation for ZK-VM execution
pub mod engine_api;

pub use config::ZKVMExecutionLayerConfig;
/// Re-export the main ZK-VM engine API and config
pub use engine_api::ZKVMEngineApi;
pub use registry_proof_gen::GeneratorRegistry;

#[test]
fn add() {
    assert!(1 + 1 == 2)
}
