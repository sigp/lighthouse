use super::*;
use types::Fork;

#[derive(Debug, Clone, Deserialize)]
pub struct SszStatic {
    pub type_name: String,
    pub value: String,
    pub serialized: String,
    pub root: String,
}

impl Test<SszStatic> for TestDoc<SszStatic> {
    fn test(&self) -> Vec<TestCaseResult<SszStatic>> {
        self.test_cases
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                let result = match tc.type_name.as_ref() {
                    "Fork" => ssz_static_test::<Fork>(&tc.value, &tc.serialized, &tc.root),
                    _ => Err(Error::FailedToParseTest(format!(
                        "Unknown type: {}",
                        tc.type_name
                    ))),
                };

                TestCaseResult {
                    case_index: i,
                    case: tc.clone(),
                    result,
                }
            })
            .collect()
    }
}

/// Execute a `ssz_generic` test case.
fn ssz_static_test<T>(value: &String, serialized: &String, root: &String) -> Result<(), Error>
where
    T: Decode + TestDecode + Debug + PartialEq<T>,
{
    let ssz =
        hex::decode(&serialized[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

    let expected = T::test_decode(value)?;

    let decoded = T::from_ssz_bytes(&ssz);

    compare_result(decoded, Some(expected))
}
