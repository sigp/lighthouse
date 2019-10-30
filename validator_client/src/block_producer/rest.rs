use super::beacon_node_block::BeaconNodeBlock;
use crate::config::ApiEncodingFormat;
use crate::error::{BeaconNodeError, PublishOutcome};
use crate::rest_client::RestClient;
use crate::service::BoxFut;
use futures::future::Future;
use futures::stream::Stream;
use hyper::client::connect::Connect;
use hyper::StatusCode;
use ssz::Decode;
use types::{BeaconBlock, EthSpec, Signature, Slot};

pub struct BeaconBlockRestClient<T: Connect> {
    endpoint: String,
    client: RestClient<T>,
}

impl<T: Connect> BeaconNodeBlock for BeaconBlockRestClient<T> {
    fn produce_beacon_block<U: EthSpec>(
        &self,
        slot: Slot,
        randao_reveal: &Signature,
    ) -> BoxFut<BeaconBlock<U>, BeaconNodeError> {
        let slot_str = format!("{}", slot).as_str();
        let randao_reveal_str: &str = serde_json::to_string(randao_reveal)
            .expect("We should always be able to serialize our signature into a string.")
            .as_str();
        Box::new(
            self.client
                .make_get_request(
                    self.endpoint.as_str(),
                    vec![("slot", slot_str), ("randao_reveal", randao_reveal_str)],
                )
                .and_then(|response| {
                    if response.status() != StatusCode::OK {
                        return futures::future::err(BeaconNodeError::RemoteFailure(format!(
                            "Received error {} from Beacon Node.",
                            response.status()
                        )));
                    }
                    response
                        .into_body()
                        .concat2()
                        .map(|chunk| chunk.iter().cloned().collect::<Vec<u8>>())
                        .map_err(|e| {
                            BeaconNodeError::RemoteFailure(format!(
                                "Error connecting to beacon node: {:?}",
                                e
                            ))
                        })
                })
                .and_then(|chunks| match self.client.config.api_encoding {
                    ApiEncodingFormat::JSON => {
                        serde_json::from_slice::<BeaconBlock<U>>(&chunks.as_slice()).map_err(|e| {
                            BeaconNodeError::DecodeFailure(format!(
                                "Cannot deserialize JSON block: {:?}",
                                e
                            ))
                        })
                    }
                    ApiEncodingFormat::YAML => {
                        serde_yaml::from_slice::<BeaconBlock<U>>(&chunks.as_slice()).map_err(|e| {
                            BeaconNodeError::DecodeFailure(format!(
                                "Cannot deserialize YAML block: {:?}",
                                e
                            ))
                        })
                    }
                    ApiEncodingFormat::SSZ => BeaconBlock::from_ssz_bytes(&chunks.as_slice())
                        .map_err(|e| {
                            BeaconNodeError::DecodeFailure(format!(
                                "Unable to deserialize SSZ block: {:?}",
                                e
                            ))
                        }),
                }),
        )
    }

    fn publish_beacon_block<U: EthSpec>(
        &self,
        block: BeaconBlock<U>,
    ) -> BoxFut<PublishOutcome, BeaconNodeError> {
        self.client
            .handle_publication(self.endpoint.as_str(), block)
    }
}
