//! Mapping from types to canonical string identifiers used in testing.
use types::blob_sidecar::BlobIdentifier;
use types::historical_summary::HistoricalSummary;
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

#[macro_export]
macro_rules! type_name_generic {
    ($typ:ident) => {
        type_name_generic!($typ, stringify!($typ));
    };
    ($typ:ident, $name:expr) => {
        impl<E: EthSpec> TypeName for $typ<E> {
            fn name() -> &'static str {
                $name
            }
        }
    };
}

type_name!(MinimalEthSpec, "minimal");
type_name!(MainnetEthSpec, "mainnet");

type_name_generic!(AggregateAndProof);
type_name_generic!(Attestation);
type_name!(AttestationData);
type_name_generic!(AttesterSlashing);
type_name_generic!(BeaconBlock);
type_name_generic!(BeaconBlockBody);
type_name_generic!(BeaconBlockBodyBase, "BeaconBlockBody");
type_name_generic!(BeaconBlockBodyAltair, "BeaconBlockBody");
type_name_generic!(BeaconBlockBodyBellatrix, "BeaconBlockBody");
type_name_generic!(BeaconBlockBodyCapella, "BeaconBlockBody");
type_name_generic!(BeaconBlockBodyDeneb, "BeaconBlockBody");
type_name!(BeaconBlockHeader);
type_name_generic!(BeaconState);
type_name!(BlobIdentifier);
type_name_generic!(BlobSidecar);
type_name!(Checkpoint);
type_name_generic!(ContributionAndProof);
type_name!(Deposit);
type_name!(DepositData);
type_name!(DepositMessage);
type_name!(Eth1Data);
type_name_generic!(ExecutionPayload);
type_name_generic!(ExecutionPayloadBellatrix, "ExecutionPayload");
type_name_generic!(ExecutionPayloadCapella, "ExecutionPayload");
type_name_generic!(ExecutionPayloadDeneb, "ExecutionPayload");
type_name_generic!(FullPayload, "ExecutionPayload");
type_name_generic!(ExecutionPayloadHeader);
type_name_generic!(ExecutionPayloadHeaderBellatrix, "ExecutionPayloadHeader");
type_name_generic!(ExecutionPayloadHeaderCapella, "ExecutionPayloadHeader");
type_name_generic!(ExecutionPayloadHeaderDeneb, "ExecutionPayloadHeader");
type_name_generic!(BlindedPayload, "ExecutionPayloadHeader");
type_name!(Fork);
type_name!(ForkData);
type_name_generic!(HistoricalBatch);
type_name_generic!(IndexedAttestation);
type_name_generic!(LightClientBootstrap);
type_name_generic!(LightClientBootstrapAltair, "LightClientBootstrap");
type_name_generic!(LightClientBootstrapCapella, "LightClientBootstrap");
type_name_generic!(LightClientBootstrapDeneb, "LightClientBootstrap");
type_name_generic!(LightClientFinalityUpdate);
type_name_generic!(LightClientFinalityUpdateAltair, "LightClientFinalityUpdate");
type_name_generic!(
    LightClientFinalityUpdateCapella,
    "LightClientFinalityUpdate"
);
type_name_generic!(LightClientFinalityUpdateDeneb, "LightClientFinalityUpdate");
type_name_generic!(LightClientHeader);
type_name_generic!(LightClientHeaderDeneb, "LightClientHeader");
type_name_generic!(LightClientHeaderCapella, "LightClientHeader");
type_name_generic!(LightClientHeaderAltair, "LightClientHeader");
type_name_generic!(LightClientOptimisticUpdate);
type_name_generic!(
    LightClientOptimisticUpdateAltair,
    "LightClientOptimisticUpdate"
);
type_name_generic!(
    LightClientOptimisticUpdateCapella,
    "LightClientOptimisticUpdate"
);
type_name_generic!(
    LightClientOptimisticUpdateDeneb,
    "LightClientOptimisticUpdate"
);
type_name_generic!(LightClientUpdate);
type_name_generic!(LightClientUpdateAltair, "LightClientUpdate");
type_name_generic!(LightClientUpdateCapella, "LightClientUpdate");
type_name_generic!(LightClientUpdateDeneb, "LightClientUpdate");
type_name_generic!(PendingAttestation);
type_name!(ProposerSlashing);
type_name_generic!(SignedAggregateAndProof);
type_name_generic!(SignedBeaconBlock);
type_name!(SignedBeaconBlockHeader);
type_name_generic!(SignedContributionAndProof);
type_name!(SignedVoluntaryExit);
type_name!(SigningData);
type_name_generic!(SyncCommitteeContribution);
type_name!(SyncCommitteeMessage);
type_name!(SyncAggregatorSelectionData);
type_name_generic!(SyncAggregate);
type_name_generic!(SyncCommittee);
type_name!(Validator);
type_name!(VoluntaryExit);
type_name!(Withdrawal);
type_name!(BlsToExecutionChange, "BLSToExecutionChange");
type_name!(SignedBlsToExecutionChange, "SignedBLSToExecutionChange");
type_name!(HistoricalSummary);
