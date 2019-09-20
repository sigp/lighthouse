use super::beacon_node_block::BeaconNodeBlock;
use crate::config::ApiEncodingFormat;
use crate::error::{BeaconNodeError, PublishOutcome};
use crate::rest_client::RestClient;
use crate::service::BoxFut;
use futures::future::Future;
use futures::stream::Stream;
use hyper::client::connect::Connect;
use hyper::StatusCode;
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
        let slot_str: &str = slot.into();
        let randao_reveal_str: &str = serde_json::to_string(randao_reveal)
            .expect("We should always be able to serialize our signature into a string.")
            .as_str();
        self.client
            .make_get_request(
                self.endpoint.as_str(),
                vec![("slot", slot_str), ("randao_reveal", randao_reveal_str)],
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
                        let block: BeaconBlock<U> = match self.client.config.api_encoding {
                            ApiEncodingFormat::JSON => serde_json::from_slice(&chunks.as_slice()),
                            ApiEncodingFormat::YAML => serde_yaml::from_slice(&chunks.as_slice()),
                        };
                        block
                    })
                    .map_err(|e| {
                        BeaconNodeError::DecodeFailure(format!("Cannot decode block: {:?}", e))
                    })
            })
    }

    fn publish_beacon_block<U: EthSpec>(
        &self,
        block: BeaconBlock<U>,
    ) -> BoxFut<PublishOutcome, BeaconNodeError> {
        self.client
            .handle_publication(self.endpoint.as_str(), block)
    }
}
