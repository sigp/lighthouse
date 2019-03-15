use protos::services_grpc::AttestationServiceClient;
use std::sync::Arc;

use attester::{BeaconNode, BeaconNodeError, PublishOutcome};
use types::{AttestationData, FreeAttestation, Slot};

pub struct AttestationGrpcClient {
    client: Arc<AttestationServiceClient>,
}

impl AttestationGrpcClient {
    pub fn new(client: Arc<AttestationServiceClient>) -> Self {
        Self { client }
    }
}

impl BeaconNode for AttestationGrpcClient {
    fn produce_attestation_data(
        &self,
        slot: Slot,
        shard: u64,
    ) -> Result<Option<AttestationData>, BeaconNodeError> {
        Err(BeaconNodeError::DecodeFailure)
    }

    fn publish_attestation_data(
        &self,
        free_attestation: FreeAttestation,
    ) -> Result<PublishOutcome, BeaconNodeError> {
        Err(BeaconNodeError::DecodeFailure)
    }
}
