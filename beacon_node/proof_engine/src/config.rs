//! Configuration for mapping EIP-8025 proof types to ERE zkVM verifiers.

use crate::{ProofEngine, ProofEngineError};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::{collections::HashSet, str::FromStr};
use types::execution::ProofType;

// Program verification keys registered by eth-act/ere-guests v0.17.0 for use with the ERE
// v0.17.1 verifier pinned by build/ere_verifier.rs. The client and release versions below
// identify the guest binaries that produced the keys.
// Ethrex stateless-validator guests from ethrex v26.0.0.
const DEFAULT_ETHREX_OPENVM_PROGRAM_VK: &str = concat!(
    "005793a02300aef9526800ee5a881400a80e7d2600ba7f8b4500f002973500b2c72d61005e74577006030619068000a2",
    "c21b53000a2fee4f0036169c2800aaaa8d6c0087fbce5b00328dc26f009fe7de5a004686562400e77e894500a128f20f",
    "00674f7c2400b38df01800309c530900a487cf0400725bac510051af497500e4abff6e00a58ac939000775b41a001a76",
    "e84100c5e8944400c94e8e1600330e6b39001cacbc5a00ca47cd51001b418e02000fe02a480009a32070002554164500",
    "d7069403007d07bf3000290ccf21008726523b00e5fd1112003d03bd4c001c6831680016a3fe4200ad7ec6300028529e",
    "3c005710de1700349b6a77004b13962f00cff00054001483f65100ab05ce6b0034174b6000bc041c0900a9b5a11a00b2",
    "6f160300615de46100935f922800d39e4a2700596ea87000ca5764770023df7b57000b1ee85e004c456d61000bdad13b",
    "003de28a5f008584cc2a00033ab1020025f59e4a00c3a9f64a00b8ef166500",
);
const DEFAULT_ETHREX_SP1_PROGRAM_VK: &str =
    "00662ca6c9db4ecb22d9ac4c320612caeac9c320f92e3ab019af4f544e35c88b";
const DEFAULT_ETHREX_ZISK_PROGRAM_VK: &str =
    "be8b29b013077f82a411403e9389ae7464b152db764e4333fdbd2c81fa157b0d";

// Reth stateless-validator guests from reth v0.1.0-rc.3.
const DEFAULT_RETH_OPENVM_PROGRAM_VK: &str = concat!(
    "0025e8d0440012375702004a22c350005a7cef2700f3654950004ba3266800e754e517007b9ca23d06030619068000a2",
    "c21b53000a2fee4f0036169c2800aaaa8d6c0087fbce5b00328dc26f009fe7de5a004686562400e77e894500a128f20f",
    "00674f7c2400b38df01800309c530900a487cf0400725bac510051af497500e4abff6e00a58ac939000775b41a001a76",
    "e84100c5e8944400c94e8e1600330e6b39001cacbc5a00ca47cd51001b418e02000fe02a480009a32070002554164500",
    "d7069403007d07bf3000290ccf21008726523b00e5fd1112003d03bd4c001c6831680016a3fe4200ad7ec6300028529e",
    "3c005710de1700349b6a77004b13962f00cff00054001483f65100ab05ce6b0034174b6000bc041c0900a9b5a11a00b2",
    "6f160300615de46100935f922800d39e4a2700596ea87000ca5764770023df7b57000b1ee85e004c456d61000bdad13b",
    "003de28a5f008584cc2a00033ab1020025f59e4a00c3a9f64a00b8ef166500",
);
const DEFAULT_RETH_SP1_PROGRAM_VK: &str =
    "00a03cbfa95559cfee3b45ef925f3f7a631181e35e774e92b040277d893511dd";
const DEFAULT_RETH_ZISK_PROGRAM_VK: &str =
    "7b0f7b082966c8155b496c2e1a371b3824b461ad2e1c2931f222c63a10004a14";

// Zesu stateless-validator guest from zesu-zkvm tests-glamsterdam-devnet@v8.1.4.
const DEFAULT_ZESU_ZISK_PROGRAM_VK: &str =
    "0e85a61f8d928667d8a771506348809f054360b27b97595eeaba611fa5760ba7";

/// Configuration for the in-process EIP-8025 proof engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofEngineConfig {
    execution_proofs: Vec<ExecutionProofConfig>,
}

impl ProofEngineConfig {
    /// Validate and construct a non-empty configuration with unique, supported proof types.
    pub fn new(execution_proofs: Vec<ExecutionProofConfig>) -> Result<Self, String> {
        if execution_proofs.is_empty() {
            return Err("`execution_proofs` must contain at least one entry".to_string());
        }

        let mut proof_types = HashSet::with_capacity(execution_proofs.len());

        for config in &execution_proofs {
            if !proof_types.insert(config.proof_type) {
                return Err(format!(
                    "duplicate configuration for proof type `{}`",
                    config.proof_type
                ));
            }
            if config.program_vk.is_empty() {
                return Err(format!(
                    "empty program verification key for proof type `{}`",
                    config.proof_type
                ));
            }
        }

        Ok(Self { execution_proofs })
    }

    /// Return the configured proof-type/verifier mappings.
    pub fn execution_proofs(&self) -> &[ExecutionProofConfig] {
        &self.execution_proofs
    }

    /// Build the proof engine described by this configuration.
    pub fn build_engine(&self) -> Result<ProofEngine, ProofEngineError> {
        #[cfg(feature = "ere-verifier")]
        {
            crate::ere::EreProofEngine::new(self.clone()).map(ProofEngine::new)
        }

        #[cfg(not(feature = "ere-verifier"))]
        {
            Err(ProofEngineError::ProofVerifierError(
                "Lighthouse was built without `ere-verifier`".to_string(),
            ))
        }
    }
}

impl Default for ProofEngineConfig {
    /// Built-in verifier configuration for every guest registered by `eth-act/ere-guests` at tag
    /// `v0.17.0`, for use with the ERE v0.17.1 verifier pinned by `build/ere_verifier.rs`.
    /// The proof-type assignments are provisional while EIP-8025 is under development.
    fn default() -> Self {
        Self::new(
            ProofType::all()
                .iter()
                .map(|proof_type| ExecutionProofConfig {
                    proof_type: *proof_type,
                    program_vk: default_program_vk(*proof_type),
                })
                .collect(),
        )
        .expect("built-in proof engine configuration is valid")
    }
}

/// The embedded program verification key for `proof_type`.
///
/// Exhaustive by construction, so a newly assigned proof type cannot be added without one.
fn default_program_vk(proof_type: ProofType) -> Vec<u8> {
    let encoded = match proof_type {
        ProofType::EthrexOpenVM => DEFAULT_ETHREX_OPENVM_PROGRAM_VK,
        ProofType::EthrexSP1 => DEFAULT_ETHREX_SP1_PROGRAM_VK,
        ProofType::EthrexZisk => DEFAULT_ETHREX_ZISK_PROGRAM_VK,
        ProofType::RethOpenVM => DEFAULT_RETH_OPENVM_PROGRAM_VK,
        ProofType::RethSP1 => DEFAULT_RETH_SP1_PROGRAM_VK,
        ProofType::RethZisk => DEFAULT_RETH_ZISK_PROGRAM_VK,
        ProofType::ZesuZisk => DEFAULT_ZESU_ZISK_PROGRAM_VK,
    };
    hex::decode(encoded).expect("embedded program verification key is valid hex")
}

impl<'de> Deserialize<'de> for ProofEngineConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Config {
            execution_proofs: Vec<ExecutionProofConfig>,
        }

        let config = Config::deserialize(deserializer)?;
        Self::new(config.execution_proofs).map_err(D::Error::custom)
    }
}

impl FromStr for ProofEngineConfig {
    type Err = serde_json::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(value)
    }
}

/// Configuration for the verifier assigned to an EIP-8025 proof type.
///
/// The zkVM is not configured: it is named by the proof type, via [`ProofType::zkvm`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProofConfig {
    /// EIP-8025 proof type handled by this verifier.
    pub proof_type: ProofType,
    /// ERE-encoded program verification key.
    #[serde(with = "serde_utils::hex_vec")]
    pub program_vk: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::execution::ZkvmKind;

    #[test]
    fn parses_and_serializes_json_config() {
        let json = format!(
            r#"{{"execution_proofs":[{{"proof_type":5,"program_vk":"0x{}"}}]}}"#,
            DEFAULT_RETH_SP1_PROGRAM_VK
        );
        let config: ProofEngineConfig = json.parse().expect("valid JSON configuration");

        assert_eq!(config.execution_proofs().len(), 1);
        assert_eq!(config.execution_proofs()[0].proof_type, ProofType::RethSP1);
        // The zkVM is named by the proof type, not carried in the JSON.
        assert_eq!(
            config.execution_proofs()[0].proof_type.zkvm(),
            ZkvmKind::Sp1
        );
        assert_eq!(
            config.execution_proofs()[0].program_vk,
            hex::decode(DEFAULT_RETH_SP1_PROGRAM_VK).expect("valid embedded key")
        );
        assert_eq!(
            serde_json::from_str::<ProofEngineConfig>(
                &serde_json::to_string(&config).expect("serialize configuration")
            )
            .expect("deserialize configuration"),
            config
        );
    }

    #[test]
    fn rejects_invalid_json_fields() {
        for json in [
            // Unassigned proof types are rejected by the codec.
            r#"{"execution_proofs":[{"proof_type":0,"program_vk":"0x00"}]}"#,
            r#"{"execution_proofs":[{"proof_type":8,"program_vk":"0x00"}]}"#,
            r#"{"execution_proofs":[{"proof_type":5,"program_vk":"00"}]}"#,
            r#"{"execution_proofs":[{"proof_type":5,"program_vk":"0x0g"}]}"#,
            r#"{"execution_proofs":[{"proof_type":5,"program_vk":"0x"}]}"#,
        ] {
            assert!(
                json.parse::<ProofEngineConfig>().is_err(),
                "accepted {json}"
            );
        }
    }

    #[test]
    fn proof_engine_config_rejects_empty_and_duplicate_proof_types() {
        let empty = ProofEngineConfig::new(vec![]);
        assert_eq!(
            empty.unwrap_err(),
            "`execution_proofs` must contain at least one entry"
        );

        let execution_proof = ProofEngineConfig::default().execution_proofs()[0].clone();
        let duplicate = ProofEngineConfig::new(vec![execution_proof.clone(), execution_proof]);
        assert_eq!(
            duplicate.unwrap_err(),
            "duplicate configuration for proof type `EthrexOpenVM`"
        );
    }

    #[test]
    fn default_config_matches_all_ere_guests_v0_17_0_program_keys() {
        let config = ProofEngineConfig::default();
        let expected = [
            (
                ProofType::EthrexOpenVM,
                ZkvmKind::Openvm,
                DEFAULT_ETHREX_OPENVM_PROGRAM_VK,
            ),
            (
                ProofType::EthrexSP1,
                ZkvmKind::Sp1,
                DEFAULT_ETHREX_SP1_PROGRAM_VK,
            ),
            (
                ProofType::EthrexZisk,
                ZkvmKind::Zisk,
                DEFAULT_ETHREX_ZISK_PROGRAM_VK,
            ),
            (
                ProofType::RethOpenVM,
                ZkvmKind::Openvm,
                DEFAULT_RETH_OPENVM_PROGRAM_VK,
            ),
            (
                ProofType::RethSP1,
                ZkvmKind::Sp1,
                DEFAULT_RETH_SP1_PROGRAM_VK,
            ),
            (
                ProofType::RethZisk,
                ZkvmKind::Zisk,
                DEFAULT_RETH_ZISK_PROGRAM_VK,
            ),
            (
                ProofType::ZesuZisk,
                ZkvmKind::Zisk,
                DEFAULT_ZESU_ZISK_PROGRAM_VK,
            ),
        ];

        assert_eq!(config.execution_proofs().len(), expected.len());
        for (config, (proof_type, zkvm_kind, program_vk)) in
            config.execution_proofs().iter().zip(expected)
        {
            assert_eq!(
                (config.proof_type, config.proof_type.zkvm()),
                (proof_type, zkvm_kind)
            );
            assert_eq!(hex::encode(&config.program_vk), program_vk);
        }
    }

    #[test]
    fn default_config_covers_every_assigned_proof_type() {
        let config = ProofEngineConfig::default();

        for proof_type in ProofType::all() {
            assert!(
                config
                    .execution_proofs()
                    .iter()
                    .any(|config| config.proof_type == *proof_type),
                "no verifier configured for {proof_type:?}"
            );
        }
    }
}
