use clap::ArgMatches;
use eth2_wallet::PlainText;
use rand::{distributions::Alphanumeric, Rng};
use std::fs::create_dir_all;
use std::path::{Path, PathBuf};

/// The `Alphanumeric` crate only generates a-z, A-Z, 0-9, therefore it has a range of 62
/// characters.
///
/// 62**48 is greater than 255**32, therefore this password has more bits of entropy than a byte
/// array of length 32.
const DEFAULT_PASSWORD_LEN: usize = 48;

pub fn random_password() -> PlainText {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(DEFAULT_PASSWORD_LEN)
        .collect::<String>()
        .into_bytes()
        .into()
}

pub fn ensure_dir_exists<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let path = path.as_ref();

    if !path.exists() {
        create_dir_all(path).map_err(|e| format!("Unable to create {:?}: {:?}", path, e))?;
    }

    Ok(())
}

pub fn base_wallet_dir(matches: &ArgMatches, arg: &'static str) -> Result<PathBuf, String> {
    clap_utils::parse_path_with_default_in_home_dir(
        matches,
        arg,
        PathBuf::new().join(".lighthouse").join("wallets"),
    )
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

    bytes.to_vec()
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
