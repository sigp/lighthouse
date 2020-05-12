#![cfg(feature = "unencrypted_keys")]

use crate::{Error, ValidatorDir};
use eth2_keystore::PlainText;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use std::fs::File;
use std::io::Read;
use types::{Keypair, PublicKey, SecretKey};

impl ValidatorDir {
    pub fn load_unencrypted_voting_keypair(&self) -> Result<Keypair, Error> {
        let path = self.dir.join("voting_keypair");

        if !path.exists() {
            return Err(Error::SszKeypairError(format!(
                "Keypair file does not exist: {:?}",
                path
            )));
        }

        let mut bytes = vec![];

        File::open(&path)
            .map_err(|e| Error::SszKeypairError(format!("Unable to open keypair file: {}", e)))?
            .read_to_end(&mut bytes)
            .map_err(|e| Error::SszKeypairError(format!("Unable to read keypair file: {}", e)))?;

        let bytes: PlainText = bytes.into();

        SszEncodableKeypair::from_ssz_bytes(bytes.as_bytes())
            .map(Into::into)
            .map_err(|e| Error::SszKeypairError(format!("Unable to decode keypair: {:?}", e)))
    }
}

/// A helper struct to allow SSZ enc/dec for a `Keypair`.
#[derive(Encode, Decode)]
struct SszEncodableKeypair {
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
