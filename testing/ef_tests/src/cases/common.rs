use crate::decode::{log_file_access, yaml_decode};
use crate::{Error, testing_spec};
use ssz::Encode;
use std::collections::HashSet;
use std::fmt::Debug;
use std::fs;
use std::path::Path;
use types::{ChainSpec, Config, EthSpec, ForkName};

/// Load the case `config.yaml`, which lists only the fields of its own fork. Fields the case does
/// not set come from the testing spec.
pub(super) fn load_config<E: EthSpec>(
    path: &Path,
    fork_name: ForkName,
) -> Result<Option<Config>, Error> {
    let config_path = path.join("config.yaml");
    if !config_path.is_file() {
        return Ok(None);
    }

    log_file_access(&config_path);
    let case_config = fs::read_to_string(&config_path).map_err(|e| {
        Error::FailedToParseTest(format!("Unable to load {}: {e:?}", config_path.display()))
    })?;
    let base_config =
        yaml_serde::to_string(&Config::from_chain_spec::<E>(&testing_spec::<E>(fork_name)))
            .map_err(|e| Error::FailedToParseTest(format!("{e:?}")))?;

    let case_keys = top_level_entries(&case_config)
        .into_iter()
        .map(|(key, _)| key)
        .collect::<HashSet<_>>();
    let mut config = case_config.clone();
    for (key, entry) in top_level_entries(&base_config) {
        if !case_keys.contains(key) {
            config.push('\n');
            config.push_str(entry);
        }
    }
    yaml_decode(&config).map(Some)
}

/// Split a YAML mapping into its top-level `(key, entry)` pairs. An entry runs until the next line
/// that starts a new top-level key.
fn top_level_entries(yaml: &str) -> Vec<(&str, &str)> {
    let mut entries = vec![];
    let mut entry_start = None;
    let mut offset = 0;
    for line in yaml.split_inclusive('\n') {
        if line.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            if let Some(start) = entry_start {
                entries.push(&yaml[start..offset]);
            }
            entry_start = Some(offset);
        }
        offset += line.len();
    }
    if let Some(start) = entry_start {
        entries.push(&yaml[start..]);
    }
    entries
        .into_iter()
        .filter_map(|entry| Some((entry.split(':').next()?.trim(), entry.trim_end())))
        .collect()
}

pub(super) fn testing_spec_with_config<E: EthSpec>(
    fork_name: ForkName,
    config: Option<&Config>,
) -> Result<ChainSpec, Error> {
    let spec = testing_spec::<E>(fork_name);
    match config {
        Some(config) => config.apply_to_chain_spec::<E>(&spec).ok_or_else(|| {
            Error::FailedToParseTest("config does not match the preset or slot duration".into())
        }),
        None => Ok(spec),
    }
}

/// Trait for types that can be used in SSZ static tests.
pub trait SszStaticType: Encode + Clone + PartialEq + Debug + Sync {}

impl<T> SszStaticType for T where T: Encode + Clone + PartialEq + Debug + Sync {}

#[macro_export]
macro_rules! impl_bls_load_case {
    ($case_name:ident) => {
        use $crate::decode::yaml_decode_file;
        impl LoadCase for $case_name {
            fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
                yaml_decode_file(&path)
            }
        }
    };

    ($case_name:ident, $sub_path_name:expr) => {
        use $crate::decode::yaml_decode_file;
        impl LoadCase for $case_name {
            fn load_from_dir(path: &Path, _fork_name: ForkName) -> Result<Self, Error> {
                yaml_decode_file(&path.join($sub_path_name))
            }
        }
    };
}
