use super::*;
use types::Fork;

pub trait TestDecode: Sized {
    /// Decode an object from the test specification YAML.
    fn test_decode(string: &String) -> Result<Self, Error>;
}

/// Basic types can general be decoded with the `parse` fn if they implement `str::FromStr`.
macro_rules! impl_via_parse {
    ($ty: ty) => {
        impl TestDecode for $ty {
            fn test_decode(string: &String) -> Result<Self, Error> {
                string
                    .parse::<Self>()
                    .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))
            }
        }
    };
}

impl_via_parse!(u8);
impl_via_parse!(u16);
impl_via_parse!(u32);
impl_via_parse!(u64);

/// Some `ethereum-types` methods have a `str::FromStr` implementation that expects `0x`-prefixed
/// hex, so we use `from_dec_str` instead.
macro_rules! impl_via_from_dec_str {
    ($ty: ty) => {
        impl TestDecode for $ty {
            fn test_decode(string: &String) -> Result<Self, Error> {
                Self::from_dec_str(string).map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))
            }
        }
    };
}

impl_via_from_dec_str!(U128);
impl_via_from_dec_str!(U256);

/// Types that already implement `serde::Deserialize` can be decoded using `serde_yaml`.
macro_rules! impl_via_serde_yaml {
    ($ty: ty) => {
        impl TestDecode for $ty {
            fn test_decode(string: &String) -> Result<Self, Error> {
                serde_yaml::from_str(string)
                    .map_err(|e| Error::FailedToParseTest(format!("{:?}", e)))
            }
        }
    };
}

impl_via_serde_yaml!(Fork);
