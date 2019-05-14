use super::*;

#[derive(Debug, Clone, Deserialize)]
pub struct SszGeneric {
    #[serde(alias = "type")]
    pub type_name: String,
    pub valid: bool,
    pub value: Option<String>,
    pub ssz: Option<String>,
}

impl Test for TestDocCases<SszGeneric> {
    fn test(&self) -> Vec<TestCaseResult> {
        self.test_cases
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                let result = if let Some(ssz) = &tc.ssz {
                    match tc.type_name.as_ref() {
                        "uint8" => ssz_generic_test::<u8>(tc.valid, ssz, &tc.value),
                        "uint16" => ssz_generic_test::<u16>(tc.valid, ssz, &tc.value),
                        "uint32" => ssz_generic_test::<u32>(tc.valid, ssz, &tc.value),
                        "uint64" => ssz_generic_test::<u64>(tc.valid, ssz, &tc.value),
                        "uint128" => ssz_generic_test::<U128>(tc.valid, ssz, &tc.value),
                        "uint256" => ssz_generic_test::<U256>(tc.valid, ssz, &tc.value),
                        _ => Err(Error::FailedToParseTest(format!(
                            "Unknown type: {}",
                            tc.type_name
                        ))),
                    }
                } else {
                    // Skip tests that do not have an ssz field.
                    //
                    // See: https://github.com/ethereum/eth2.0-specs/issues/1079
                    Ok(())
                };

                TestCaseResult::new(i, tc, result)
            })
            .collect()
    }
}

/// Execute a `ssz_generic` test case.
fn ssz_generic_test<T>(
    should_be_ok: bool,
    ssz: &String,
    value: &Option<String>,
) -> Result<(), Error>
where
    T: Decode + TestDecode + Debug + PartialEq<T>,
{
    let ssz = hex::decode(&ssz[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

    // We do not cater for the scenario where the test is valid but we are not passed any SSZ.
    if should_be_ok && value.is_none() {
        panic!("Unexpected test input. Cannot pass without value.")
    }

    let expected = if let Some(string) = value {
        Some(T::test_decode(string)?)
    } else {
        None
    };

    let decoded = T::from_ssz_bytes(&ssz);

    compare_result(decoded, expected)
}
