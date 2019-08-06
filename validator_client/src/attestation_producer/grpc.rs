use super::beacon_node_attestation::BeaconNodeAttestation;
use crate::block_producer::{BeaconNodeError, PublishOutcome};
use protos::services_grpc::AttestationServiceClient;
use ssz::{Decode, Encode};

use protos::services::{
    Attestation as GrpcAttestation, ProduceAttestationDataRequest, PublishAttestationRequest,
};
use types::{Attestation, AttestationData, EthSpec, Slot};

impl BeaconNodeAttestation for AttestationServiceClient {
    fn produce_attestation_data(
        &self,
        slot: Slot,
        shard: u64,
    ) -> Result<AttestationData, BeaconNodeError> {
        let mut req = ProduceAttestationDataRequest::new();
        req.set_slot(slot.as_u64());
        req.set_shard(shard);

        let reply = self
            .produce_attestation_data(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        let attestation_data =
            AttestationData::from_ssz_bytes(reply.get_attestation_data().get_ssz())
                .map_err(|_| BeaconNodeError::DecodeFailure)?;
        Ok(attestation_data)
    }

    fn publish_attestation<T: EthSpec>(
        &self,
        attestation: Attestation<T>,
    ) -> Result<PublishOutcome, BeaconNodeError> {
        let mut req = PublishAttestationRequest::new();

        let ssz = attestation.as_ssz_bytes();

        let mut grpc_attestation = GrpcAttestation::new();
        grpc_attestation.set_ssz(ssz);

        req.set_attestation(grpc_attestation);

        let reply = self
            .publish_attestation(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        if reply.get_success() {
            Ok(PublishOutcome::Valid)
        } else {
            // TODO: distinguish between different errors
            Ok(PublishOutcome::InvalidAttestation(
                "Publish failed".to_string(),
            ))
        }
    }
}
