//! The functionality in this module is only required for backward compatibility with the old
//! method of key generation (unencrypted, SSZ-encoded keypairs). It should be removed as soon as
//! we're confident that no-one is using these keypairs anymore (hopefully mid-June 2020).
#![cfg(feature = "unencrypted_keys")]

use bls::{BLS_PUBLIC_KEY_BYTE_SIZE as PK_LEN, BLS_SECRET_KEY_BYTE_SIZE as SK_LEN};
use eth2_keystore::PlainText;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use types::{Keypair, PublicKey, SecretKey};

/// Read a keypair from disk, using the old format where keys were stored as unencrypted
/// SSZ-encoded keypairs.
///
/// This only exists as compatibility with the old scheme and should not be implemented on any new
/// features.
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

    if bytes.len() != PK_LEN + SK_LEN {
        return Err(format!("Invalid keypair byte length: {}", bytes.len()));
    }

    let pk_bytes = &bytes.as_bytes()[..PK_LEN];
    let sk_bytes = &bytes.as_bytes()[PK_LEN..];

    let pk = PublicKey::from_bytes(pk_bytes)
        .map_err(|e| format!("Unable to decode public key: {:?}", e))?;

    let sk = SecretKey::from_bytes(sk_bytes)
        .map_err(|e| format!("Unable to decode secret key: {:?}", e))?;

    Ok(Keypair { pk, sk })
}
