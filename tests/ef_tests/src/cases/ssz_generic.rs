use super::*;
use crate::case_result::compare_result;
use ethereum_types::{U128, U256};
use serde_derive::Deserialize;
use ssz::Decode;
use std::fmt::Debug;

#[derive(Debug, Clone, Deserialize)]
pub struct SszGeneric {
    #[serde(alias = "type")]
    pub type_name: String,
    pub valid: bool,
    pub value: Option<String>,
    pub ssz: Option<String>,
}

impl YamlDecode for SszGeneric {
    fn yaml_decode(yaml: &String) -> Result<Self, Error> {
        Ok(serde_yaml::from_str(&yaml.as_str()).unwrap())
    }
}

impl Case for SszGeneric {
    fn result(&self) -> Result<(), Error> {
        if let Some(ssz) = &self.ssz {
            match self.type_name.as_ref() {
                "uint8" => ssz_generic_test::<u8>(self.valid, ssz, &self.value),
                "uint16" => ssz_generic_test::<u16>(self.valid, ssz, &self.value),
                "uint32" => ssz_generic_test::<u32>(self.valid, ssz, &self.value),
                "uint64" => ssz_generic_test::<u64>(self.valid, ssz, &self.value),
                "uint128" => ssz_generic_test::<U128>(self.valid, ssz, &self.value),
                "uint256" => ssz_generic_test::<U256>(self.valid, ssz, &self.value),
                _ => Err(Error::FailedToParseTest(format!(
                    "Unknown type: {}",
                    self.type_name
                ))),
            }
        } else {
            // Skip tests that do not have an ssz field.
            //
            // See: https://github.com/ethereum/eth2.0-specs/issues/1079
            Ok(())
        }
    }
}

/// Execute a `ssz_generic` test case.
fn ssz_generic_test<T>(
    should_be_ok: bool,
    ssz: &String,
    value: &Option<String>,
) -> Result<(), Error>
where
    T: Decode + YamlDecode + Debug + PartialEq<T>,
{
    let ssz = hex::decode(&ssz[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

    // We do not cater for the scenario where the test is valid but we are not passed any SSZ.
    if should_be_ok && value.is_none() {
        panic!("Unexpected test input. Cannot pass without value.")
    }

    let expected = if let Some(string) = value {
        Some(T::yaml_decode(string)?)
    } else {
        None
    };

    let decoded = T::from_ssz_bytes(&ssz);

    compare_result(&decoded, &expected)
}
