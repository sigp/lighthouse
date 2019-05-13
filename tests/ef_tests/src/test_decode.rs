use super::*;

pub trait TestDecode: Sized {
    fn test_decode(string: &String) -> Result<Self, Error>;
}

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
