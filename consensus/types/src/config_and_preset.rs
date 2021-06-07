use crate::{AltairPreset, BasePreset, ChainSpec, Config, EthSpec};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fusion of a runtime-config with the compile-time preset values.
///
/// Mostly useful for the API.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ConfigAndPreset {
    #[serde(flatten)]
    pub config: Config,

    #[serde(flatten)]
    pub base_preset: BasePreset,
    #[serde(flatten)]
    pub altair_preset: AltairPreset,

    /// The `extra_fields` map allows us to gracefully decode fields intended for future hard forks.
    #[serde(flatten)]
    pub extra_fields: HashMap<String, String>,
}

impl ConfigAndPreset {
    pub fn from_chain_spec<T: EthSpec>(spec: &ChainSpec) -> Self {
        let config = Config::from_chain_spec::<T>(spec);
        let base_preset = BasePreset::from_chain_spec::<T>(spec);
        let altair_preset = AltairPreset::from_chain_spec::<T>(spec);
        let extra_fields = HashMap::new();

        Self {
            config,
            base_preset,
            altair_preset,
            extra_fields,
        }
    }

    /// Add fields that were previously part of the config but are now constants.
    pub fn make_backwards_compat(&mut self, spec: &ChainSpec) {
        let hex_string = |value: &[u8]| format!("0x{}", hex::encode(&value));
        let u32_hex = |v: u32| hex_string(&v.to_le_bytes());
        let u8_hex = |v: u8| hex_string(&v.to_le_bytes());
        let fields = vec![
            ("config_name", self.config.preset_base.clone()),
            (
                "bls_withdrawal_prefix",
                u8_hex(spec.bls_withdrawal_prefix_byte),
            ),
            (
                "domain_beacon_proposer",
                u32_hex(spec.domain_beacon_proposer),
            ),
            (
                "domain_beacon_attester",
                u32_hex(spec.domain_beacon_attester),
            ),
            ("domain_randao", u32_hex(spec.domain_randao)),
            ("domain_deposit", u32_hex(spec.domain_deposit)),
            ("domain_voluntary_exit", u32_hex(spec.domain_voluntary_exit)),
            (
                "domain_selection_proof",
                u32_hex(spec.domain_selection_proof),
            ),
            (
                "domain_aggregate_and_proof",
                u32_hex(spec.domain_aggregate_and_proof),
            ),
            (
                "target_aggregators_per_committee",
                spec.target_aggregators_per_committee.to_string(),
            ),
            (
                "random_subnets_per_validator",
                spec.random_subnets_per_validator.to_string(),
            ),
            (
                "epochs_per_random_subnet_subscription",
                spec.epochs_per_random_subnet_subscription.to_string(),
            ),
        ];
        for (key, value) in fields {
            self.extra_fields.insert(key.to_uppercase(), value);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::MainnetEthSpec;
    use std::fs::OpenOptions;
    use tempfile::NamedTempFile;

    #[test]
    fn extra_fields_round_trip() {
        let tmp_file = NamedTempFile::new().expect("failed to create temp file");
        let writer = OpenOptions::new()
            .read(false)
            .write(true)
            .open(tmp_file.as_ref())
            .expect("error opening file");
        let mainnet_spec = ChainSpec::mainnet();
        let mut yamlconfig = ConfigAndPreset::from_chain_spec::<MainnetEthSpec>(&mainnet_spec);
        let (k1, v1) = ("SAMPLE_HARDFORK_KEY1", "123456789");
        let (k2, v2) = ("SAMPLE_HARDFORK_KEY2", "987654321");
        yamlconfig.extra_fields.insert(k1.into(), v1.into());
        yamlconfig.extra_fields.insert(k2.into(), v2.into());
        serde_yaml::to_writer(writer, &yamlconfig).expect("failed to write or serialize");

        let reader = OpenOptions::new()
            .read(true)
            .write(false)
            .open(tmp_file.as_ref())
            .expect("error while opening the file");
        let from: ConfigAndPreset =
            serde_yaml::from_reader(reader).expect("error while deserializing");
        assert_eq!(from, yamlconfig);
    }
}
