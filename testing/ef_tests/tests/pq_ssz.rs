//! Exact PQ SSZ artifact coverage. See pq_support for isolated artifact selection.
#![cfg(all(feature = "ef_tests", feature = "spec-minimal"))]

mod pq_support;

use ef_tests::{SszStaticHandler, SszStaticTHCHandler, SszStaticWithSpecHandler};
use types::*;

type Spec = MinimalEthSpec;

macro_rules! ssz_case {
    ($name:ident, $handler:ident, $typ:ty, $canonical:literal) => {
        #[test]
        #[ignore = "requires explicitly selected PQ reference artifact"]
        fn $name() {
            pq_support::run_handler_as($handler::<$typ, Spec>::default(), "ssz_static", $canonical);
        }
    };
}

ssz_case!(
    aggregate_and_proof,
    SszStaticHandler,
    AggregateAndProofPq<Spec>,
    "AggregateAndProof"
);
ssz_case!(
    attestation,
    SszStaticHandler,
    AttestationPq<Spec>,
    "Attestation"
);
ssz_case!(
    attestation_data,
    SszStaticHandler,
    AttestationData,
    "AttestationData"
);
ssz_case!(
    attester_slashing,
    SszStaticHandler,
    AttesterSlashingPq<Spec>,
    "AttesterSlashing"
);
ssz_case!(
    beacon_block,
    SszStaticWithSpecHandler,
    BeaconBlock<Spec>,
    "BeaconBlock"
);
ssz_case!(
    beacon_block_body,
    SszStaticHandler,
    BeaconBlockBodyPq<Spec>,
    "BeaconBlockBody"
);
ssz_case!(
    beacon_block_header,
    SszStaticHandler,
    BeaconBlockHeader,
    "BeaconBlockHeader"
);
ssz_case!(
    beacon_state,
    SszStaticTHCHandler,
    BeaconState<Spec>,
    "BeaconState"
);
ssz_case!(builder, SszStaticHandler, Builder, "Builder");
ssz_case!(
    builder_deposit_request,
    SszStaticHandler,
    BuilderDepositRequest,
    "BuilderDepositRequest"
);
ssz_case!(
    builder_exit_request,
    SszStaticHandler,
    BuilderExitRequest,
    "BuilderExitRequest"
);
ssz_case!(
    builder_pending_payment,
    SszStaticHandler,
    BuilderPendingPayment,
    "BuilderPendingPayment"
);
ssz_case!(
    builder_pending_withdrawal,
    SszStaticHandler,
    BuilderPendingWithdrawal,
    "BuilderPendingWithdrawal"
);
ssz_case!(
    builder_preregistration,
    SszStaticHandler,
    BuilderPreregistration,
    "BuilderPreregistration"
);
ssz_case!(
    builder_preregistration_request,
    SszStaticHandler,
    BuilderPreregistrationRequest,
    "BuilderPreregistrationRequest"
);
ssz_case!(checkpoint, SszStaticHandler, Checkpoint, "Checkpoint");
ssz_case!(
    consolidation_request,
    SszStaticHandler,
    ConsolidationRequest,
    "ConsolidationRequest"
);
ssz_case!(
    data_column_sidecar,
    SszStaticHandler,
    DataColumnSidecarGloas<Spec>,
    "DataColumnSidecar"
);
ssz_case!(
    data_columns_by_root_identifier,
    SszStaticWithSpecHandler,
    DataColumnsByRootIdentifier<Spec>,
    "DataColumnsByRootIdentifier"
);
ssz_case!(deposit, SszStaticHandler, Deposit, "Deposit");
ssz_case!(deposit_data, SszStaticHandler, DepositData, "DepositData");
ssz_case!(
    deposit_message,
    SszStaticHandler,
    DepositMessage,
    "DepositMessage"
);
ssz_case!(
    deposit_request,
    SszStaticHandler,
    DepositRequest,
    "DepositRequest"
);
ssz_case!(eth1_data, SszStaticHandler, Eth1Data, "Eth1Data");
ssz_case!(
    execution_payload,
    SszStaticHandler,
    ExecutionPayloadGloas<Spec>,
    "ExecutionPayload"
);
ssz_case!(
    execution_payload_bid,
    SszStaticHandler,
    ExecutionPayloadBidGloas<Spec>,
    "ExecutionPayloadBid"
);
ssz_case!(
    execution_payload_envelope,
    SszStaticHandler,
    ExecutionPayloadEnvelopePq<Spec>,
    "ExecutionPayloadEnvelope"
);
ssz_case!(
    execution_requests,
    SszStaticHandler,
    ExecutionRequestsPq<Spec>,
    "ExecutionRequests"
);
ssz_case!(fork, SszStaticHandler, Fork, "Fork");
ssz_case!(fork_data, SszStaticHandler, ForkData, "ForkData");
ssz_case!(
    historical_summary,
    SszStaticHandler,
    HistoricalSummary,
    "HistoricalSummary"
);
ssz_case!(
    indexed_attestation,
    SszStaticHandler,
    IndexedAttestationPq<Spec>,
    "IndexedAttestation"
);
ssz_case!(
    new_payload_request,
    SszStaticHandler,
    NewPayloadRequestPq<Spec>,
    "NewPayloadRequest"
);
ssz_case!(
    payload_attestation_data,
    SszStaticHandler,
    PayloadAttestationData,
    "PayloadAttestationData"
);
ssz_case!(
    payload_attestation_message,
    SszStaticHandler,
    PayloadAttestationMessagePq,
    "PayloadAttestationMessage"
);
ssz_case!(
    pending_consolidation,
    SszStaticHandler,
    PendingConsolidation,
    "PendingConsolidation"
);
ssz_case!(
    pending_deposit,
    SszStaticHandler,
    PendingDeposit,
    "PendingDeposit"
);
ssz_case!(
    pending_partial_withdrawal,
    SszStaticHandler,
    PendingPartialWithdrawal,
    "PendingPartialWithdrawal"
);
ssz_case!(
    proposer_preferences,
    SszStaticHandler,
    ProposerPreferences,
    "ProposerPreferences"
);
ssz_case!(
    proposer_slashing,
    SszStaticHandler,
    ProposerSlashingPq,
    "ProposerSlashing"
);
ssz_case!(
    signed_aggregate_and_proof,
    SszStaticHandler,
    SignedAggregateAndProofPq<Spec>,
    "SignedAggregateAndProof"
);
ssz_case!(
    signed_beacon_block,
    SszStaticWithSpecHandler,
    SignedBeaconBlock<Spec>,
    "SignedBeaconBlock"
);
ssz_case!(
    signed_beacon_block_header,
    SszStaticHandler,
    SignedBeaconBlockHeaderPq,
    "SignedBeaconBlockHeader"
);
ssz_case!(
    signed_execution_payload_bid,
    SszStaticHandler,
    SignedExecutionPayloadBidPq<Spec>,
    "SignedExecutionPayloadBid"
);
ssz_case!(
    signed_execution_payload_envelope,
    SszStaticHandler,
    SignedExecutionPayloadEnvelopePq<Spec>,
    "SignedExecutionPayloadEnvelope"
);
ssz_case!(
    signed_proposer_preferences,
    SszStaticHandler,
    SignedProposerPreferencesPq,
    "SignedProposerPreferences"
);
ssz_case!(signing_data, SszStaticHandler, SigningData, "SigningData");
ssz_case!(
    single_attestation,
    SszStaticHandler,
    SingleAttestationPq,
    "SingleAttestation"
);
ssz_case!(validator, SszStaticHandler, Validator, "Validator");
ssz_case!(
    validator_preregistration,
    SszStaticHandler,
    ValidatorPreregistration,
    "ValidatorPreregistration"
);
ssz_case!(
    validator_preregistration_request,
    SszStaticHandler,
    ValidatorPreregistrationRequest,
    "ValidatorPreregistrationRequest"
);
ssz_case!(
    voluntary_exit_request,
    SszStaticHandler,
    VoluntaryExitRequest,
    "VoluntaryExitRequest"
);
ssz_case!(withdrawal, SszStaticHandler, Withdrawal, "Withdrawal");
ssz_case!(
    withdrawal_request,
    SszStaticHandler,
    WithdrawalRequest,
    "WithdrawalRequest"
);

// These network types intentionally have no production JSON API. Adapt the fixture YAML
// into native values, then exercise their real SSZ encoder, decoder and tree hash.
mod partial_columns {
    use super::*;
    use ef_tests::{Case, Error, Handler, LoadCase};
    use serde::Deserialize;
    use ssz::{Decode, Encode};
    use std::{fs, path::Path};
    use tree_hash::TreeHash;

    #[derive(Debug, Deserialize)]
    struct GroupIdYaml {
        beacon_block_root: Hash256,
        slot: Slot,
    }
    #[derive(Debug, Deserialize)]
    struct MetadataYaml {
        available: CellBitmap<Spec>,
        requests: CellBitmap<Spec>,
    }
    #[derive(Debug, Deserialize)]
    struct SidecarYaml {
        cells_present_bitmap: CellBitmap<Spec>,
        #[serde(with = "ssz_types::serde_utils::prog_list_of_hex_fixed_vec")]
        partial_column: ssz_types::ProgressiveVariableList<
            Cell<Spec>,
            <Spec as EthSpec>::MaxBlobCommitmentsPerBlock,
        >,
        kzg_proofs: ssz_types::ProgressiveVariableList<
            kzg::KzgProof,
            <Spec as EthSpec>::MaxBlobCommitmentsPerBlock,
        >,
    }
    #[derive(Debug)]
    struct PartialCase<const KIND: u8> {
        yaml: String,
        serialized: Vec<u8>,
        root: Hash256,
    }
    impl<const KIND: u8> LoadCase for PartialCase<KIND> {
        fn load_from_dir(path: &Path, _: ForkName) -> Result<Self, Error> {
            let read = |name: &str| {
                fs::read(path.join(name))
                    .map_err(|error| Error::FailedToParseTest(error.to_string()))
            };
            #[derive(Deserialize)]
            struct Roots {
                root: Hash256,
            }
            Ok(Self {
                yaml: String::from_utf8(read("value.yaml")?)
                    .map_err(|error| Error::FailedToParseTest(error.to_string()))?,
                serialized: snap::raw::Decoder::new()
                    .decompress_vec(&read("serialized.ssz_snappy")?)
                    .map_err(|error| Error::FailedToParseTest(error.to_string()))?,
                root: yaml_serde::from_slice::<Roots>(&read("roots.yaml")?)
                    .map_err(|error| Error::FailedToParseTest(error.to_string()))?
                    .root,
            })
        }
    }
    fn check<T: Encode + Decode + TreeHash + PartialEq + std::fmt::Debug>(
        value: T,
        bytes: &[u8],
        root: Hash256,
    ) -> Result<(), Error> {
        if value.as_ssz_bytes() != bytes || value.ssz_bytes_len() != bytes.len() {
            return Err(Error::NotEqual("native SSZ serialization differs".into()));
        }
        let decoded = T::from_ssz_bytes(bytes)
            .map_err(|error| Error::FailedComparison(format!("native SSZ decode: {error:?}")))?;
        if decoded != value {
            return Err(Error::NotEqual("native SSZ decoded value differs".into()));
        }
        if value.tree_hash_root() != root {
            return Err(Error::NotEqual("native tree hash differs".into()));
        }
        Ok(())
    }
    impl<const KIND: u8> Case for PartialCase<KIND> {
        fn result(&self, _: usize, _: ForkName) -> Result<(), Error> {
            let parse_error =
                |error: yaml_serde::Error| Error::FailedToParseTest(error.to_string());
            match KIND {
                0 => {
                    let value: GroupIdYaml =
                        yaml_serde::from_str(&self.yaml).map_err(parse_error)?;
                    check(
                        PartialDataColumnGroupId {
                            beacon_block_root: value.beacon_block_root,
                            slot: value.slot,
                        },
                        &self.serialized,
                        self.root,
                    )
                }
                1 => {
                    let value: MetadataYaml =
                        yaml_serde::from_str(&self.yaml).map_err(parse_error)?;
                    check(
                        PartialDataColumnPartsMetadata::<Spec> {
                            available: value.available,
                            requests: value.requests,
                        },
                        &self.serialized,
                        self.root,
                    )
                }
                _ => {
                    let value: SidecarYaml =
                        yaml_serde::from_str(&self.yaml).map_err(parse_error)?;
                    check(
                        PartialDataColumnSidecarGloas::<Spec> {
                            cells_present_bitmap: value.cells_present_bitmap,
                            column: value.partial_column,
                            kzg_proofs: value.kzg_proofs,
                        },
                        &self.serialized,
                        self.root,
                    )
                }
            }
        }
    }
    struct PartialHandler<const KIND: u8>;
    impl<const KIND: u8> Handler for PartialHandler<KIND> {
        type Case = PartialCase<KIND>;
        fn runner_name() -> &'static str {
            "ssz_static"
        }
        fn handler_name(&self) -> String {
            "partial_columns".into()
        }
    }
    #[test]
    #[ignore = "requires explicitly selected PQ reference artifact"]
    fn group_id() {
        pq_support::run_handler_as(
            PartialHandler::<0>,
            "ssz_static",
            "PartialDataColumnGroupID",
        );
    }
    #[test]
    #[ignore = "requires explicitly selected PQ reference artifact"]
    fn metadata() {
        pq_support::run_handler_as(
            PartialHandler::<1>,
            "ssz_static",
            "PartialDataColumnPartsMetadata",
        );
    }
    #[test]
    #[ignore = "requires explicitly selected PQ reference artifact"]
    fn sidecar() {
        pq_support::run_handler_as(
            PartialHandler::<2>,
            "ssz_static",
            "PartialDataColumnSidecar",
        );
    }
}

/// Explicit accounting, not conformance claims, for spec helper containers without a
/// corresponding Lighthouse SSZ type. Never substitute a newly invented test-only type.
#[test]
#[ignore = "requires explicitly selected PQ reference artifact"]
fn unsupported_spec_helpers() {
    for name in ["Eth1Block", "PowBlock", "MatrixEntry"] {
        let root = pq_support::fixture_root();
        let mut cases = Vec::new();
        for suite in std::fs::read_dir(root.join("ssz_static").join(name)).unwrap() {
            for entry in std::fs::read_dir(suite.unwrap().path()).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    cases.push(serde_json::json!({
                        "case": path.strip_prefix(&root).unwrap().to_string_lossy(),
                        "outcome": "unsupported",
                        "detail": "No corresponding Lighthouse SSZ container; not tested"
                    }));
                }
            }
        }
        cases.sort_by_key(|case| case["case"].as_str().unwrap().to_owned());
        assert!(!cases.is_empty());
        let report = serde_json::json!({"runner": "ssz_static", "handler": name,
            "counts": {"unsupported": cases.len()}, "cases": cases});
        println!("PQ_REFERENCE ssz_static/{name}: {}", report["counts"]);
        if let Some(output) = std::env::var_os("PQ_REFERENCE_RESULTS_DIR") {
            let dir = std::path::PathBuf::from(output).join("ssz_static");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join(format!("{name}.json")),
                serde_json::to_vec_pretty(&report).unwrap(),
            )
            .unwrap();
        }
    }
}
