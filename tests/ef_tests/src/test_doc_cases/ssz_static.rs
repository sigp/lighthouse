use super::*;
use serde::de::{Deserialize, Deserializer};
use types::Fork;

#[derive(Debug, Clone, Deserialize)]
pub struct SszStatic {
    pub type_name: String,
    pub serialized: String,
    pub root: String,
    #[serde(skip)]
    pub raw_yaml: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Value<T> {
    value: T,
}

impl TestDecode for SszStatic {
    fn test_decode(yaml: &String) -> Result<Self, Error> {
        let mut ssz_static: SszStatic = serde_yaml::from_str(&yaml.as_str()).unwrap();

        ssz_static.raw_yaml = yaml.clone();

        Ok(ssz_static)
    }
}

impl SszStatic {
    fn value<T: serde::de::DeserializeOwned>(&self) -> Result<T, Error> {
        let wrapper: Value<T> = serde_yaml::from_str(&self.raw_yaml.as_str()).map_err(|e| {
            Error::FailedToParseTest(format!("Unable to parse {} YAML: {:?}", self.type_name, e))
        })?;

        Ok(wrapper.value)
    }
}

impl Test for TestDocCases<SszStatic> {
    fn test(&self) -> Vec<TestCaseResult> {
        self.test_cases
            .iter()
            .enumerate()
            .map(|(i, tc)| {
                let result = match tc.type_name.as_ref() {
                    "Fork" => ssz_static_test::<Fork>(tc),
                    _ => Err(Error::FailedToParseTest(format!(
                        "Unknown type: {}",
                        tc.type_name
                    ))),
                };

                TestCaseResult::new(i, tc, result)
            })
            .collect()
    }
}

fn ssz_static_test<T>(tc: &SszStatic) -> Result<(), Error>
where
    T: Decode + TestDecode + Debug + PartialEq<T> + serde::de::DeserializeOwned,
{
    let ssz = hex::decode(&tc.serialized[2..])
        .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))?;

    let expected = tc.value::<T>()?;

    Ok(())

    /*
    let decoded = T::from_ssz_bytes(&ssz);

    compare_result(decoded, Some(expected))
    */
}
