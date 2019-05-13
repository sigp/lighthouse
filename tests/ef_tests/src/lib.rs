use error::Error;
use ethereum_types::{U128, U256};
use serde_derive::Deserialize;
use ssz::Decode;
use std::fmt::Debug;
use test_decode::TestDecode;

mod error;
mod test_decode;

#[derive(Debug, Deserialize)]
pub struct TestDoc<T> {
    pub title: String,
    pub summary: String,
    pub forks_timeline: String,
    pub forks: Vec<String>,
    pub config: String,
    pub runner: String,
    pub handler: String,
    pub test_cases: Vec<T>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SszGenericCase {
    #[serde(alias = "type")]
    pub type_name: String,
    pub valid: bool,
    pub value: String,
    pub ssz: Option<String>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct TestCaseResult<T> {
    pub case_index: usize,
    pub case: T,
    pub result: Result<(), Error>,
}

pub trait Test<T> {
    fn test(&self) -> Vec<TestCaseResult<T>>;
}

impl Test<SszGenericCase> for TestDoc<SszGenericCase> {
    fn test(&self) -> Vec<TestCaseResult<SszGenericCase>> {
        self.test_cases
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                let result = if let Some(ssz) = &tc.ssz {
                    match tc.type_name.as_ref() {
                        "uint8" => compare_decoding::<u8>(tc.valid, ssz, &tc.value),
                        "uint16" => compare_decoding::<u16>(tc.valid, ssz, &tc.value),
                        "uint32" => compare_decoding::<u32>(tc.valid, ssz, &tc.value),
                        "uint64" => compare_decoding::<u64>(tc.valid, ssz, &tc.value),
                        "uint128" => compare_decoding::<U128>(tc.valid, ssz, &tc.value),
                        "uint256" => compare_decoding::<U256>(tc.valid, ssz, &tc.value),
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

                TestCaseResult {
                    case_index: i,
                    case: tc.clone(),
                    result,
                }
            })
            .collect()
    }
}

fn compare_decoding<T>(should_be_ok: bool, ssz: &String, value: &String) -> Result<(), Error>
where
    T: Decode + TestDecode + Debug + PartialEq<T>,
{
    let ssz = hex::decode(&ssz[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

    let expected = if should_be_ok {
        Some(T::test_decode(value)?)
    } else {
        None
    };

    let decoded = T::from_ssz_bytes(&ssz);

    compare_result(decoded, expected)
}

fn compare_result<T, E>(result: Result<T, E>, expected: Option<T>) -> Result<(), Error>
where
    T: PartialEq<T> + Debug,
    E: Debug,
{
    match (result, expected) {
        // Pass: The should have failed and did fail.
        (Err(_), None) => Ok(()),
        // Fail: The test failed when it should have produced a result (fail).
        (Err(e), Some(expected)) => Err(Error::NotEqual(format!(
            "Got {:?} expected {:?}",
            e, expected
        ))),
        // Fail: The test produced a result when it should have failed (fail).
        (Ok(result), None) => Err(Error::DidntFail(format!("Got {:?}", result))),
        // Potential Pass: The test should have produced a result, and it did.
        (Ok(result), Some(expected)) => {
            if result == expected {
                Ok(())
            } else {
                Err(Error::NotEqual(format!(
                    "Got {:?} expected {:?}",
                    result, expected
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
