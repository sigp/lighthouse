//! EIP-8025 proof verification.
//!
//! The default client delegates verification to a locally operated proof-engine service. Builds
//! with the `ere-verifier` feature can also construct an in-process verifier backed by ERE's C
//! API.

mod config;
#[cfg(feature = "ere-verifier")]
pub mod ere;

use sensitive_url::SensitiveUrl;
use serde::Deserialize;
use std::time::Duration;
use types::execution::{ExecutionProof, ProofType};

pub use config::{ExecutionProofConfig, ProofEngineConfig};

pub const DEFAULT_VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

const PATH_PROOF_VERIFICATIONS: &str = "/v1/execution_proof_verifications";

/// Errors raised while initializing or running a proof verifier.
#[derive(Debug)]
pub enum ProofEngineError {
    HttpClient(String),
    InvalidUrl(String),
    InvalidResponse(String),
    /// The configured in-process verifier could not initialize or complete verification.
    ProofVerifierError(String),
    /// No in-process verifier is configured for the proof's EIP-8025 proof type.
    UnconfiguredProofType(ProofType),
}

/// Outcome of proof verification. `Invalid` means the artifact does not verify; it says nothing
/// about the validity of the payload it claims to prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerificationOutcome {
    Valid,
    Invalid,
}

/// Interface implemented by in-process execution-proof verifiers.
pub trait ProofEngineT: Send + Sync + 'static {
    fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError>;
}

#[derive(Deserialize)]
struct VerifyResponse {
    status: VerifyStatus,
}

#[derive(Deserialize, Clone, Copy)]
enum VerifyStatus {
    #[serde(rename = "VALID")]
    Valid,
    #[serde(rename = "INVALID")]
    Invalid,
}

pub struct ProofEngine {
    client: reqwest::Client,
    url: SensitiveUrl,
}

impl ProofEngine {
    /// Construct a client for a locally operated proof-engine service.
    pub fn new(url: SensitiveUrl) -> Result<Self, ProofEngineError> {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_VERIFY_TIMEOUT)
            .build()
            .map_err(|error| ProofEngineError::HttpClient(error.to_string()))?;
        Ok(Self { client, url })
    }

    /// EIP-8025 `ProofEngine.verify_execution_proof`.
    pub async fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        let mut url = self.url.expose_full().clone();
        url.set_path(PATH_PROOF_VERIFICATIONS);
        let response: VerifyResponse = self
            .client
            .post(url)
            .query(&[
                (
                    "new_payload_request_root",
                    format!("{:?}", proof.public_input.new_payload_request_root),
                ),
                (
                    "successful_validation",
                    proof.public_input.successful_validation.to_string(),
                ),
                ("chain_id", proof.public_input.chain_id.to_string()),
                ("schema_id", proof.public_input.schema_id.to_string()),
                ("proof_type", proof.proof_type.to_u8().to_string()),
            ])
            .header("content-type", "application/octet-stream")
            .body(proof.proof_data.to_vec())
            .send()
            .await
            .map_err(|error| ProofEngineError::HttpClient(error.to_string()))?
            .error_for_status()
            .map_err(|error| ProofEngineError::HttpClient(error.to_string()))?
            .json()
            .await
            .map_err(|error| ProofEngineError::InvalidResponse(error.to_string()))?;

        Ok(match response.status {
            VerifyStatus::Valid => ProofVerificationOutcome::Valid,
            VerifyStatus::Invalid => ProofVerificationOutcome::Invalid,
        })
    }
}
