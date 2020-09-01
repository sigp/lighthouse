//! Provides functions that are used for key/account management across multiple crates in the
//! Lighthouse project.

use eth2_keystore::Keystore;
use eth2_wallet::Wallet;
use rand::{distributions::Alphanumeric, Rng};
use serde_derive::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io;
use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub mod validator_definitions;

pub use eth2_keystore;
pub use eth2_wallet::PlainText;

/// The `Alphanumeric` crate only generates a-z, A-Z, 0-9, therefore it has a range of 62
/// characters.
///
/// 62**48 is greater than 255**32, therefore this password has more bits of entropy than a byte
/// array of length 32.
const DEFAULT_PASSWORD_LEN: usize = 48;

/// Returns the "default" path where a wallet should store its password file.
pub fn default_wallet_password_path<P: AsRef<Path>>(wallet_name: &str, secrets_dir: P) -> PathBuf {
    secrets_dir.as_ref().join(format!("{}.pass", wallet_name))
}

/// Returns a password for a wallet, where that password is loaded from the "default" path.
pub fn default_wallet_password<P: AsRef<Path>>(
    wallet: &Wallet,
    secrets_dir: P,
) -> Result<PlainText, io::Error> {
    let path = default_wallet_password_path(wallet.name(), secrets_dir);
    fs::read(path).map(|bytes| PlainText::from(strip_off_newlines(bytes)))
}

/// Returns the "default" path where a keystore should store its password file.
pub fn default_keystore_password_path<P: AsRef<Path>>(
    keystore: &Keystore,
    secrets_dir: P,
) -> PathBuf {
    secrets_dir
        .as_ref()
        .join(format!("0x{}", keystore.pubkey()))
}

/// Reads a password file into a Zeroize-ing `PlainText` struct, with new-lines removed.
pub fn read_password<P: AsRef<Path>>(path: P) -> Result<PlainText, io::Error> {
    fs::read(path).map(strip_off_newlines).map(Into::into)
}

/// Creates a file with `600 (-rw-------)` permissions.
pub fn create_with_600_perms<P: AsRef<Path>>(path: P, bytes: &[u8]) -> Result<(), io::Error> {
    let path = path.as_ref();

    let mut file = File::create(&path)?;

    let mut perm = file.metadata()?.permissions();

    perm.set_mode(0o600);

    file.set_permissions(perm)?;

    file.write_all(bytes)?;

    Ok(())
}

/// Generates a random alphanumeric password of length `DEFAULT_PASSWORD_LEN`.
pub fn random_password() -> PlainText {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(DEFAULT_PASSWORD_LEN)
        .collect::<String>()
        .into_bytes()
        .into()
}

/// Remove any number of newline or carriage returns from the end of a vector of bytes.
pub fn strip_off_newlines(mut bytes: Vec<u8>) -> Vec<u8> {
    let mut strip_off = 0;
    for (i, byte) in bytes.iter().rev().enumerate() {
        if *byte == b'\n' || *byte == b'\r' {
            strip_off = i + 1;
        } else {
            break;
        }
    }
    bytes.truncate(bytes.len() - strip_off);
    bytes
}

/// Reads a password from TTY or stdin if `use_stdin == true`.
pub fn read_password_from_user(use_stdin: bool) -> Result<ZeroizeString, String> {
    let result = if use_stdin {
        rpassword::prompt_password_stderr("")
            .map_err(|e| format!("Error reading from stdin: {}", e))
    } else {
        rpassword::read_password_from_tty(None)
            .map_err(|e| format!("Error reading from tty: {}", e))
    };

    result.map(ZeroizeString::from)
}

/// Provides a new-type wrapper around `String` that is zeroized on `Drop`.
///
/// Useful for ensuring that password memory is zeroed-out on drop.
#[derive(Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
#[serde(transparent)]
pub struct ZeroizeString(String);

impl From<String> for ZeroizeString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<[u8]> for ZeroizeString {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod test {
    use super::strip_off_newlines;

    #[test]
    fn test_strip_off() {
        let expected = "hello world".as_bytes().to_vec();

        assert_eq!(
            strip_off_newlines("hello world\n".as_bytes().to_vec()),
            expected
        );
        assert_eq!(
            strip_off_newlines("hello world\n\n\n\n".as_bytes().to_vec()),
            expected
        );
        assert_eq!(
            strip_off_newlines("hello world\r".as_bytes().to_vec()),
            expected
        );
        assert_eq!(
            strip_off_newlines("hello world\r\r\r\r\r".as_bytes().to_vec()),
            expected
        );
        assert_eq!(
            strip_off_newlines("hello world\r\n".as_bytes().to_vec()),
            expected
        );
        assert_eq!(
            strip_off_newlines("hello world\r\n\r\n".as_bytes().to_vec()),
            expected
        );
        assert_eq!(
            strip_off_newlines("hello world".as_bytes().to_vec()),
            expected
        );
    }
}
