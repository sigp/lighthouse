use super::beacon_node_attestation::BeaconNodeAttestation;
use crate::block_producer::{BeaconNodeError, PublishOutcome};
use protos::services_grpc::AttestationServiceClient;
use ssz::{ssz_encode, Decodable};

use protos::services::{
    Attestation as GrpcAttestation, ProduceAttestationDataRequest, PublishAttestationRequest,
};
use types::{Attestation, AttestationData, Slot};

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

        dbg!("Produced Attestation Data");

        let (attestation_data, _index) =
            AttestationData::ssz_decode(reply.get_attestation_data().get_ssz(), 0)
                .map_err(|_| BeaconNodeError::DecodeFailure)?;
        Ok(attestation_data)
    }

    fn publish_attestation(
        &self,
        attestation: Attestation,
    ) -> Result<PublishOutcome, BeaconNodeError> {
        let mut req = PublishAttestationRequest::new();

        let ssz = ssz_encode(&attestation);

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
