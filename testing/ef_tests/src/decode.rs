use super::*;
use std::fs;
use std::path::Path;

pub fn yaml_decode<T: serde::de::DeserializeOwned>(string: &str) -> Result<T, Error> {
    serde_yaml::from_str(string).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))
}

pub fn yaml_decode_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Error> {
    fs::read_to_string(path)
        .map_err(|e| {
            Error::FailedToParseTest(format!("Unable to load {}: {:?}", path.display(), e))
        })
        .and_then(|s| yaml_decode(&s))
}

pub fn ssz_decode_file<T: ssz::Decode>(path: &Path) -> Result<T, Error> {
    fs::read(path)
        .map_err(|e| {
            Error::FailedToParseTest(format!("Unable to load {}: {:?}", path.display(), e))
        })
        .and_then(|s| {
            T::from_ssz_bytes(&s).map_err(|e| {
                Error::FailedToParseTest(format!(
                    "Unable to parse SSZ at {}: {:?}",
                    path.display(),
                    e
                ))
            })
        })
}
