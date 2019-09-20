use super::beacon_node_duties::BeaconNodeDuties;
use crate::config::ApiEncodingFormat;
use crate::duties::epoch_duties::{EpochDuties, EpochDuty};
use crate::error::{BeaconNodeError, PublishOutcome};
use crate::rest_client::RestClient;
use crate::service::BoxFut;
use futures::future::Future;
use futures::stream::Stream;
use hyper::client::connect::Connect;
use hyper::StatusCode;
use itertools::Itertools;
use rest_api::helpers::parse_pubkey;
use rest_api::ValidatorDuty;
use std::collections::HashMap;
use types::{AttestationDuty, BeaconBlock, Epoch, EthSpec, PublicKey, Signature, Slot};

pub struct ValidatorServiceRestClient<T: Connect> {
    endpoint: String,
    client: RestClient<T>,
}

impl<T: Connect> BeaconNodeDuties for ValidatorServiceRestClient<T> {
    fn request_duties(
        &self,
        epoch: Epoch,
        pub_keys: &[PublicKey],
    ) -> BoxFut<EpochDuties, BeaconNodeError> {
        let mut parameters_vec = pub_keys
            .into_iter()
            .map(|pk| pk.as_hex_string())
            .map(|pk| ("pub_keys", pk.as_str()))
            .collect_vec();
        parameters_vec.push(("epoch", epoch.into()));
        self.client
            .make_get_request(self.endpoint.as_str(), parameters_vec)
            .and_then(|response| {
                if (response.status() != StatusCode::OK) {
                    return futures::future::err(BeaconNodeError::RemoteFailure(format!(
                        "Received error {} from Beacon Node.",
                        response.status()
                    )));
                }
                let mut epoch_duties: HashMap<PublicKey, Option<EpochDuty>> = HashMap::new();
                response
                    .into_body()
                    .concat2()
                    .map(|chunk| chunk.iter().cloned().collect::<Vec<u8>>())
                    .and_then(|chunks| {
                        let duties: Vec<ValidatorDuty> = match self.client.config.api_encoding {
                            ApiEncodingFormat::JSON => serde_json::from_slice(&chunks.as_slice()),
                            ApiEncodingFormat::YAML => serde_yaml::from_slice(&chunks.as_slice()),
                            ApiEncodingFormat::SSZ => ssz::from(&chunks.as_slice()),
                        };
                        duties.into_iter()
                    })
                    .map(|duty: ValidatorDuty| {
                        match duty.attestation_slot {
                            Some(d) => (duty.validator_pubkey, Some(EpochDuty {
                                block_production_slot: duty.block_proposal_slot,
                                attestation_duty: AttestationDuty {
                                        slot: d,
                                        shard: duty.attestation_shard.expect("Attestation shard should never be present, when slot is not!"),
                                        //TODO: Need to provide these from the beacon node or calculate them!
                                        committee_index: 0 as usize,
                                        committee_len: 1 as usize,
                                    }
                                })),
                            None => (duty.validator_pubkey, None)
                        }
                    })
                    .map_err(|e| {
                        BeaconNodeError::DecodeFailure(format!(
                            "Cannot decode validator duties: {:?}",
                            e
                        ))
                    })
                    .and_then(move |(pk, duty)| {
                        let pubkey = parse_pubkey(pk.as_str()).map_err(|e| {
                            BeaconNodeError::DecodeFailure(format!("Unable to parse pubkey from beacon node: {:?}", e))
                        })?;
                        epoch_duties.insert(pubkey, duty)
                    })

            })
            .and_then()
    }
}
