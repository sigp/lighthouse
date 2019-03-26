use protos::services_grpc::AttestationServiceClient;
use std::sync::Arc;

use attester::{BeaconNode, BeaconNodeError, PublishOutcome};
use protos::services::ProduceAttestationDataRequest;
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
        let mut req = ProduceAttestationDataRequest::new();
        req.set_slot(slot.as_u64());
        req.set_shard(shard);

        let reply = self
            .client
            .produce_attestation(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        // TODO: return correct Attestation
        Err(BeaconNodeError::DecodeFailure)
    }

    fn publish_attestation(
        &self,
        free_attestation: FreeAttestation,
    ) -> Result<PublishOutcome, BeaconNodeError> {
        // TODO: return correct PublishOutcome
        Err(BeaconNodeError::DecodeFailure)
    }
}
