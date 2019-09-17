use super::beacon_node_attestation::BeaconNodeAttestation;
use crate::config::ApiEncodingFormat;
use crate::error::{BeaconNodeError, PublishOutcome};
use crate::rest_client::RestClient;
use crate::service::BoxFut;
use futures::future::Future;
use futures::stream::Stream;
use hyper::client::connect::Connect;
use hyper::StatusCode;
use types::{Attestation, AttestationData, BeaconBlock, EthSpec, Signature, Slot};

pub struct BeaconBlockRestClient<T: Connect> {
    endpoint: String,
    client: RestClient<T>,
}

impl<T: Connect> BeaconNodeAttestation for BeaconBlockRestClient<T> {
    fn produce_attestation_data<U: EthSpec>(
        &self,
        slot: Slot,
        shard: u64,
    ) -> BoxFut<AttestationData, BeaconNodeError> {
        let slot_str: &str = slot.into();
        let shard_str: &str = shard.into();
        self.client
            .make_get_request(
                self.endpoint.as_str(),
                vec![("slot", slot_str), ("shard", shard_str)],
            )
            .and_then(|response| {
                if (response.status() != StatusCode::OK) {
                    return futures::future::err(BeaconNodeError::RemoteFailure(format!(
                        "Received error {} from Beacon Node.",
                        response.status()
                    )));
                }
                response
                    .into_body()
                    .concat2()
                    .map(|chunk| chunk.iter().cloned().collect::<Vec<u8>>())
                    .and_then(|chunks| {
                        let attestation: Attestation<U> = match self.client.api_encoding {
                            ApiEncodingFormat::JSON => serde_json::from_slice(&chunks.as_slice()),
                            ApiEncodingFormat::YAML => serde_yaml::from_slice(&chunks.as_slice()),
                        };
                        attestation
                    })
                    .map_err(|e| {
                        BeaconNodeError::DecodeFailure(format!(
                            "Cannot decode attestation: {:?}",
                            e
                        ))
                    })
                    .map(|a| a.data)
            })
    }

    fn publish_attestation<U: EthSpec>(
        &self,
        attestation: Attestation<U>,
    ) -> BoxFut<PublishOutcome, BeaconNodeError> {
        self.client
            .handle_publication(self.endpoint.as_str(), attestation)
    }
}
