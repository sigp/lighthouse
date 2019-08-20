use super::*;
use crate::bls_setting::BlsSetting;
use crate::case_result::compare_beacon_state_results_without_caches;
use serde_derive::Deserialize;
use state_processing::per_block_processing::{process_attestations, VerifySignatures};
use types::{Attestation, BeaconState, EthSpec};

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct OperationsAttestation<E: EthSpec> {
    pub description: String,
    pub bls_setting: Option<BlsSetting>,
    pub pre: BeaconState<E>,
    pub attestation: Attestation<E>,
    pub post: Option<BeaconState<E>>,
}

impl<E: EthSpec> YamlDecode for OperationsAttestation<E> {
    fn yaml_decode(yaml: &str) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml).unwrap())
    }
}

impl<E: EthSpec> Case for OperationsAttestation<E> {
    fn description(&self) -> String {
        self.description.clone()
    }

    fn result(&self, _case_index: usize) -> Result<(), Error> {
        let spec = &E::default_spec();

        self.bls_setting.unwrap_or_default().check()?;

        let mut state = self.pre.clone();
        let attestation = self.attestation.clone();
        let mut expected = self.post.clone();

        // Processing requires the epoch cache.
        state.build_all_caches(spec).unwrap();

        let result = process_attestations(&mut state, &[attestation], VerifySignatures::True, spec);

        let mut result = result.and_then(|_| Ok(state));

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
