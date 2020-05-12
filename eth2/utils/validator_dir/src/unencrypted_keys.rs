#![cfg(feature = "unencrypted_keys")]

use eth2_keystore::PlainText;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use types::{Keypair, PublicKey, SecretKey};

pub fn load_unencrypted_keypair<P: AsRef<Path>>(path: P) -> Result<Keypair, String> {
    let path = path.as_ref();

    if !path.exists() {
        return Err(format!("Keypair file does not exist: {:?}", path));
    }

    let mut bytes = vec![];

    File::open(&path)
        .map_err(|e| format!("Unable to open keypair file: {}", e))?
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Unable to read keypair file: {}", e))?;

    let bytes: PlainText = bytes.into();

    SszEncodableKeypair::from_ssz_bytes(bytes.as_bytes())
        .map(Into::into)
        .map_err(|e| format!("Unable to decode keypair: {:?}", e))
}

/// A helper struct to allow SSZ enc/dec for a `Keypair`.
#[derive(Encode, Decode)]
pub struct SszEncodableKeypair {
    pk: PublicKey,
    sk: SecretKey,
}

impl Into<Keypair> for SszEncodableKeypair {
    fn into(self) -> Keypair {
        Keypair {
            sk: self.sk,
            pk: self.pk,
        }
    }
}

impl From<Keypair> for SszEncodableKeypair {
    fn from(kp: Keypair) -> Self {
        Self {
            sk: kp.sk,
            pk: kp.pk,
        }
    }
}
