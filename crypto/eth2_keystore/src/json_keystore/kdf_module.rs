//! Defines the JSON representation of the "kdf" module.
//!
//! This file **MUST NOT** contain any logic beyond what is required to serialize/deserialize the
//! data structures. Specifically, there should not be any actual crypto logic in this file.

use super::hex_bytes::HexBytes;
use crate::{keystore::log2_int, Error, DKLEN, SALT_SIZE};
use hmac::{Hmac, Mac, NewMac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::convert::TryFrom;

/// KDF module representation.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfModule {
    pub function: KdfFunction,
    pub params: Kdf,
    pub message: EmptyString,
}

/// Used for ensuring serde only decodes an empty string.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EmptyString;

impl Into<String> for EmptyString {
    fn into(self) -> String {
        "".into()
    }
}

impl TryFrom<String> for EmptyString {
    type Error = &'static str;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "" => Ok(Self),
            _ => Err("kdf message must be empty"),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Kdf {
    Scrypt(Scrypt),
    Pbkdf2(Pbkdf2),
}

impl Kdf {
    pub fn function(&self) -> KdfFunction {
        match &self {
            Kdf::Pbkdf2(_) => KdfFunction::Pbkdf2,
            Kdf::Scrypt(_) => KdfFunction::Scrypt,
        }
    }

    // Validates the kdf parameters to ensure they are sufficiently secure, in addition to
    // preventing DoS attacks from excessively large parameters.
    pub fn validate_parameters(&self) -> Result<(), Error> {
        match &self {
            Kdf::Pbkdf2(params) => {
                // We always compute a derived key of 32 bytes so reject anything that
                // says otherwise.
                if params.dklen != DKLEN {
                    return Err(Error::InvalidPbkdf2Param);
                }

                // NIST Recommends suggests potential use cases where `c` of 10,000,000 is desireable.
                // As it is 10 years old this has been increased to 80,000,000. Larger values will
                // take over 1 minute to execute on an average machine.
                //
                // Reference:
                //
                // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
                if params.c > 80_000_000 {
                    return Err(Error::InvalidPbkdf2Param);
                }

                // RFC2898 declares that `c` must be a "positive integer" and the `crypto` crate panics
                // if it is `0`.
                //
                // Reference:
                //
                // https://www.ietf.org/rfc/rfc2898.txt
                if params.c < 262_144 {
                    if params.c == 0 {
                        return Err(Error::InvalidPbkdf2Param);
                    }
                    eprintln!("WARN: PBKDF2 parameters are too weak, 'c' is {}, we recommend using 262,144", params.c);
                }

                // Validate `salt` length
                if params.salt.is_empty() {
                    return Err(Error::InvalidPbkdf2Param);
                } else if params.salt.len() < SALT_SIZE / 2 {
                    eprintln!(
                        "WARN: Salt is too short {}, we recommend {}",
                        params.salt.len(),
                        SALT_SIZE
                    );
                } else if params.salt.len() > SALT_SIZE * 2 {
                    eprintln!(
                        "WARN: Salt is too long {}, we recommend {}",
                        params.salt.len(),
                        SALT_SIZE
                    );
                }

                Ok(())
            }
            Kdf::Scrypt(params) => {
                // RFC7914 declares that all these parameters must be greater than 1:
                //
                // - `N`: costParameter.
                // - `r`: blockSize.
                // - `p`: parallelizationParameter
                //
                // Reference:
                //
                // https://tools.ietf.org/html/rfc7914
                if params.n <= 1 || params.r == 0 || params.p == 0 {
                    return Err(Error::InvalidScryptParam);
                }

                // We always compute a derived key of 32 bytes so reject anything that
                // says otherwise.
                if params.dklen != DKLEN {
                    return Err(Error::InvalidScryptParam);
                }

                // Ensure that `n` is power of 2.
                if params.n != 2u32.pow(log2_int(params.n)) {
                    return Err(Error::InvalidScryptParam);
                }

                // Maximum Parameters
                //
                // Uses a u32 to store value thus maximum memory usage is 4GB.
                //
                // Note: Memory requirements = 128*n*p*r
                let mut npr: u32 = params
                    .n
                    .checked_mul(params.p)
                    .ok_or(Error::InvalidScryptParam)?;
                npr = npr.checked_mul(params.r).ok_or(Error::InvalidScryptParam)?;
                npr = npr.checked_mul(128).ok_or(Error::InvalidScryptParam)?;

                // Minimum Parameters
                let default = Scrypt::default_scrypt(vec![0u8; 32]);
                let default_npr = 128 * default.n * default.p * default.r;
                if npr < default_npr {
                    eprintln!("WARN: Scrypt parameters are too weak (n: {}, p: {}, r: {}), we recommend (n: 262,144, p: 1, r: 8)", params.n, params.p, params.r);
                }

                // Validate `salt` length
                if params.salt.is_empty() {
                    return Err(Error::InvalidScryptParam);
                } else if params.salt.len() < SALT_SIZE / 2 {
                    eprintln!(
                        "WARN: Salt is too short {}, we recommend {}",
                        params.salt.len(),
                        SALT_SIZE
                    );
                } else if params.salt.len() > SALT_SIZE * 2 {
                    eprintln!(
                        "WARN: Salt is too long {}, we recommend {}",
                        params.salt.len(),
                        SALT_SIZE
                    );
                }

                Ok(())
            }
        }
    }
}

/// PRF for use in `pbkdf2`.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Prf {
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
}

impl Prf {
    pub fn mac(&self, password: &[u8]) -> impl Mac {
        match &self {
            Prf::HmacSha256 => {
                Hmac::<Sha256>::new_varkey(password).expect("Could not derive HMAC using SHA256.")
            }
        }
    }
}

impl Default for Prf {
    fn default() -> Self {
        Prf::HmacSha256
    }
}

/// Parameters for `pbkdf2` key derivation.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pbkdf2 {
    pub c: u32,
    pub dklen: u32,
    pub prf: Prf,
    pub salt: HexBytes,
}

/// Used for ensuring that serde only decodes valid KDF functions.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum KdfFunction {
    Scrypt,
    Pbkdf2,
}

impl Into<String> for KdfFunction {
    fn into(self) -> String {
        match self {
            KdfFunction::Scrypt => "scrypt".into(),
            KdfFunction::Pbkdf2 => "pbkdf2".into(),
        }
    }
}

impl TryFrom<String> for KdfFunction {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_ref() {
            "scrypt" => Ok(KdfFunction::Scrypt),
            "pbkdf2" => Ok(KdfFunction::Pbkdf2),
            other => Err(format!("Unsupported kdf function: {}", other)),
        }
    }
}

/// Parameters for `scrypt` key derivation.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scrypt {
    pub dklen: u32,
    pub n: u32,
    pub r: u32,
    pub p: u32,
    pub salt: HexBytes,
}

impl Scrypt {
    pub fn default_scrypt(salt: Vec<u8>) -> Self {
        Self {
            dklen: DKLEN,
            n: 262144,
            p: 1,
            r: 8,
            salt: salt.into(),
        }
    }
}
