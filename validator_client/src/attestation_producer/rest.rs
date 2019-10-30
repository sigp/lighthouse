use super::beacon_node_attestation::BeaconNodeAttestation;
use crate::config::ApiEncodingFormat;
use crate::error::{BeaconNodeError, PublishOutcome};
use crate::rest_client::RestClient;
use crate::service::BoxFut;
use futures::future::Future;
use futures::stream::Stream;
use hyper::client::connect::Connect;
use hyper::StatusCode;
use ssz::Decode;
use types::{Attestation, EthSpec, Slot};

pub struct AttestationRestClient<T: Connect> {
    endpoint: String,
    client: RestClient<T>,
}

impl<T: Connect> BeaconNodeAttestation for AttestationRestClient<T> {
    fn produce_attestation_data<U: EthSpec>(
        &self,
        slot: Slot,
        shard: u64,
    ) -> BoxFut<Attestation<U>, BeaconNodeError> {
        let slot_str = format!("{}", slot).as_str();
        let shard_str = format!("{}", shard).as_str();
        Box::new(
            self.client
                .make_get_request(
                    self.endpoint.as_str(),
                    vec![("slot", slot_str), ("shard", shard_str)],
                )
                .and_then(|response| {
                    if response.status() != StatusCode::OK {
                        return futures::future::err(BeaconNodeError::RemoteFailure(format!(
                            "Received error {} from Beacon Node.",
                            response.status()
                        )));
                    }
                    futures::future::ok(response.into_body().concat2())
                })
                .map(|chunk| chunk.collect::<Vec<u8>>())
                .map_err(|e| {
                    BeaconNodeError::RemoteFailure(format!(
                        "Error connecting to beacon node: {:?}",
                        e
                    ))
                })
                .and_then(|chunks| match self.client.config.api_encoding {
                    ApiEncodingFormat::JSON => {
                        serde_json::from_slice::<Attestation<U>>(&chunks.as_slice()).map_err(|e| {
                            BeaconNodeError::DecodeFailure(format!(
                                "Unable to deserialize JSON: {:?}",
                                e
                            ))
                        })
                    }
                    ApiEncodingFormat::YAML => {
                        serde_yaml::from_slice::<Attestation<U>>(&chunks.as_slice()).map_err(|e| {
                            BeaconNodeError::DecodeFailure(format!(
                                "Unable to deserialize YAML: {:?}",
                                e
                            ))
                        })
                    }
                    ApiEncodingFormat::SSZ => {
                        <_>::from_ssz_bytes(&chunks.as_slice()).map_err(|e| {
                            BeaconNodeError::DecodeFailure(format!(
                                "Unable to deserialize SSZ: {:?}",
                                e
                            ))
                        })
                    }
                }),
        )
    }

    fn publish_attestation<U: EthSpec>(
        &self,
        attestation: Attestation<U>,
    ) -> BoxFut<PublishOutcome, BeaconNodeError> {
        self.client
            .handle_publication(self.endpoint.as_str(), attestation)
    }
}
