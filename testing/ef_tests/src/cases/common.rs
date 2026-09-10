use ssz::Encode;
use std::fmt::Debug;

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
