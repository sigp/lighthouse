use self::BlsSetting::*;
use crate::error::Error;
use serde_repr::Deserialize_repr;

#[derive(Deserialize_repr, Debug, Clone, Copy)]
#[repr(u8)]
pub enum BlsSetting {
    Flexible = 0,
    Required = 1,
    Ignored = 2,
}

impl Default for BlsSetting {
    fn default() -> Self {
        Flexible
    }
}

impl BlsSetting {
    /// Check the BLS setting and skip the test if it isn't compatible with the crypto config.
    pub fn check(self) -> Result<(), Error> {
        match self {
            Flexible => Ok(()),
            Required if !cfg!(feature = "fake_crypto") => Ok(()),
            Ignored if cfg!(feature = "fake_crypto") => Ok(()),
            _ => Err(Error::SkippedBls),
        }
    }
}
