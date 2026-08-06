//! Mapping from types to canonical string identifiers used in testing.
use types::state::HistoricalSummary;
use types::*;

pub trait TypeName {
    fn name() -> &'static str;
}

#[macro_export]
macro_rules! type_name {
    ($typ:ident) => {
        type_name!($typ, stringify!($typ));
    };
    ($typ:ident, $name:expr) => {
        impl TypeName for $typ {
            fn name() -> &'static str {
                $name
            }
        }
    };
}

type_name!(AggregateAndProof);
type_name!(AggregateAndProofBase, "AggregateAndProof");
type_name!(AggregateAndProofElectra, "AggregateAndProof");
type_name!(AggregateAndProofGloas, "AggregateAndProof");
type_name!(Attestation);
type_name!(AttestationBase, "Attestation");
type_name!(AttestationElectra, "Attestation");
type_name!(AttestationGloas, "Attestation");
type_name!(AttestationData);
type_name!(AttesterSlashing);
type_name!(AttesterSlashingBase, "AttesterSlashing");
type_name!(AttesterSlashingElectra, "AttesterSlashing");
type_name!(AttesterSlashingGloas, "AttesterSlashing");
type_name!(BeaconBlock);
type_name!(BeaconBlockBody);
type_name!(BeaconBlockBodyBase, "BeaconBlockBody");
type_name!(BeaconBlockBodyAltair, "BeaconBlockBody");
type_name!(BeaconBlockBodyBellatrix, "BeaconBlockBody");
type_name!(BeaconBlockBodyCapella, "BeaconBlockBody");
type_name!(BeaconBlockBodyDeneb, "BeaconBlockBody");
type_name!(BeaconBlockBodyElectra, "BeaconBlockBody");
type_name!(BeaconBlockBodyFulu, "BeaconBlockBody");
type_name!(BeaconBlockBodyGloas, "BeaconBlockBody");
type_name!(BeaconBlockBodyHeze, "BeaconBlockBody");
type_name!(BeaconBlockHeader);
type_name!(BeaconState);
type_name!(BlobIdentifier);
type_name!(DataColumnsByRootIdentifier, "DataColumnsByRootIdentifier");
type_name!(BlobSidecar);
type_name!(DataColumnSidecar);
type_name!(DataColumnSidecarFulu, "DataColumnSidecar");
type_name!(DataColumnSidecarGloas, "DataColumnSidecar");
type_name!(Checkpoint);
type_name!(ConsolidationRequest);
type_name!(ContributionAndProof);
type_name!(Deposit);
type_name!(DepositData);
type_name!(DepositMessage);
type_name!(DepositRequest);
type_name!(Eth1Data);
type_name!(Builder);
type_name!(BuilderDepositRequest);
type_name!(BuilderExitRequest);
type_name!(BuilderPendingPayment);
type_name!(BuilderPendingWithdrawal);
type_name!(WithdrawalRequest);
type_name!(ExecutionPayload);
type_name!(ExecutionPayloadBellatrix, "ExecutionPayload");
type_name!(ExecutionPayloadCapella, "ExecutionPayload");
type_name!(ExecutionPayloadDeneb, "ExecutionPayload");
type_name!(ExecutionPayloadElectra, "ExecutionPayload");
type_name!(ExecutionPayloadFulu, "ExecutionPayload");
type_name!(ExecutionPayloadGloas, "ExecutionPayload");
type_name!(ExecutionPayloadHeze, "ExecutionPayload");
type_name!(FullPayload, "ExecutionPayload");
type_name!(ExecutionPayloadHeader);
type_name!(ExecutionPayloadHeaderBellatrix, "ExecutionPayloadHeader");
type_name!(ExecutionPayloadHeaderCapella, "ExecutionPayloadHeader");
type_name!(ExecutionPayloadHeaderDeneb, "ExecutionPayloadHeader");
type_name!(ExecutionPayloadHeaderElectra, "ExecutionPayloadHeader");
type_name!(ExecutionPayloadHeaderFulu, "ExecutionPayloadHeader");
type_name!(ExecutionPayloadBid);
type_name!(SignedExecutionPayloadBid);
type_name!(ExecutionRequestsElectra, "ExecutionRequests");
type_name!(ExecutionRequestsGloas, "ExecutionRequests");
type_name!(ExecutionPayloadEnvelope);
type_name!(SignedExecutionPayloadEnvelope);
type_name!(BlindedPayload, "ExecutionPayloadHeader");
type_name!(Fork);
type_name!(ForkData);
type_name!(HistoricalBatch);
type_name!(IndexedAttestation);
type_name!(IndexedAttestationBase, "IndexedAttestation");
type_name!(IndexedAttestationElectra, "IndexedAttestation");
type_name!(IndexedAttestationGloas, "IndexedAttestation");
type_name!(IndexedPayloadAttestation);
type_name!(LightClientBootstrap);
type_name!(LightClientBootstrapAltair, "LightClientBootstrap");
type_name!(LightClientBootstrapCapella, "LightClientBootstrap");
type_name!(LightClientBootstrapDeneb, "LightClientBootstrap");
type_name!(LightClientBootstrapElectra, "LightClientBootstrap");
type_name!(LightClientBootstrapFulu, "LightClientBootstrap");
type_name!(LightClientFinalityUpdate);
type_name!(LightClientFinalityUpdateAltair, "LightClientFinalityUpdate");
type_name!(
    LightClientFinalityUpdateCapella,
    "LightClientFinalityUpdate"
);
type_name!(LightClientFinalityUpdateDeneb, "LightClientFinalityUpdate");
type_name!(
    LightClientFinalityUpdateElectra,
    "LightClientFinalityUpdate"
);
type_name!(LightClientFinalityUpdateFulu, "LightClientFinalityUpdate");
type_name!(LightClientHeader);
type_name!(LightClientHeaderAltair, "LightClientHeader");
type_name!(LightClientHeaderCapella, "LightClientHeader");
type_name!(LightClientHeaderDeneb, "LightClientHeader");
type_name!(LightClientHeaderElectra, "LightClientHeader");
type_name!(LightClientHeaderFulu, "LightClientHeader");
type_name!(LightClientOptimisticUpdate);
type_name!(
    LightClientOptimisticUpdateAltair,
    "LightClientOptimisticUpdate"
);
type_name!(
    LightClientOptimisticUpdateCapella,
    "LightClientOptimisticUpdate"
);
type_name!(
    LightClientOptimisticUpdateDeneb,
    "LightClientOptimisticUpdate"
);
type_name!(
    LightClientOptimisticUpdateElectra,
    "LightClientOptimisticUpdate"
);
type_name!(
    LightClientOptimisticUpdateFulu,
    "LightClientOptimisticUpdate"
);
type_name!(LightClientUpdate);
type_name!(LightClientUpdateAltair, "LightClientUpdate");
type_name!(LightClientUpdateCapella, "LightClientUpdate");
type_name!(LightClientUpdateDeneb, "LightClientUpdate");
type_name!(LightClientUpdateElectra, "LightClientUpdate");
type_name!(LightClientUpdateFulu, "LightClientUpdate");
type_name!(PendingAttestation);
type_name!(PayloadAttestation);
type_name!(PayloadAttestationData);
type_name!(PayloadAttestationMessage);
type_name!(PendingConsolidation);
type_name!(PendingPartialWithdrawal);
type_name!(PendingDeposit);
type_name!(ProposerSlashing);
type_name!(ProposerPreferences);
type_name!(SignedProposerPreferences);
type_name!(SignedAggregateAndProof);
type_name!(SignedAggregateAndProofBase, "SignedAggregateAndProof");
type_name!(SignedAggregateAndProofElectra, "SignedAggregateAndProof");
type_name!(SignedAggregateAndProofGloas, "SignedAggregateAndProof");
type_name!(SignedBeaconBlock);
type_name!(SignedBeaconBlockHeader);
type_name!(SignedContributionAndProof);
type_name!(SignedVoluntaryExit);
type_name!(SigningData);
type_name!(SingleAttestation);
type_name!(SyncCommitteeContribution);
type_name!(SyncCommitteeMessage);
type_name!(SyncAggregatorSelectionData);
type_name!(SyncAggregate);
type_name!(SyncCommittee);
type_name!(Validator);
type_name!(VoluntaryExit);
type_name!(Withdrawal);
type_name!(BlsToExecutionChange, "BLSToExecutionChange");
type_name!(SignedBlsToExecutionChange, "SignedBLSToExecutionChange");
type_name!(HistoricalSummary);
