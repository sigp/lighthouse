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

#[derive(Debug, Deserialize)]
pub struct SszGenericCase {
    #[serde(alias = "type")]
    pub type_name: String,
    pub valid: bool,
    pub value: String,
    pub ssz: Option<String>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct TestCaseResult {
    pub description: String,
    pub result: Result<(), Error>,
}

pub trait Test {
    fn test(&self) -> Vec<TestCaseResult>;
}

impl Test for TestDoc<SszGenericCase> {
    fn test(&self) -> Vec<TestCaseResult> {
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
                    description: format!("Case {}: {:?}", i, tc),
                    result,
                }
            })
            .collect()
    }
}

fn compare_decoding<T>(should_pass: bool, ssz: &String, value: &String) -> Result<(), Error>
where
    T: Decode + TestDecode + Debug + PartialEq<T>,
{
    let ssz = hex::decode(&ssz[2..]).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;
    let expected = T::test_decode(value)?;

    let decoded = T::from_ssz_bytes(&ssz);

    if should_pass {
        let decoded = decoded.map_err(|e| Error::NotEqual(format!("{:?}", e)))?;

        if decoded != expected {
            Err(Error::NotEqual(format!("{:?} != {:?}", decoded, expected)))
        } else {
            Ok(())
        }
    } else {
        if let Ok(decoded) = decoded {
            Err(Error::DidntFail(format!("Decoded as {:?}", decoded)))
        } else {
            Ok(())
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
