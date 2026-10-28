use crate::decode::yaml_decode_file;
use crate::{Error, testing_spec};
use ssz::Encode;
use std::fmt::Debug;
use std::path::Path;
use types::{ChainSpec, Config, EthSpec, ForkName};

pub(super) fn load_config(path: &Path) -> Result<Option<Config>, Error> {
    let config_path = path.join("config.yaml");
    if config_path.is_file() {
        yaml_decode_file(&config_path).map(Some)
    } else {
        Ok(None)
    }
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
