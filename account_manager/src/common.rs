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
const NEWLINE_SLASH_N: u8 = 10;
const NEWLINE_SLASH_R: u8 = 13;

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

pub fn strip_off_newline_codes(bytes: &mut Vec<u8>) -> Vec<u8> {
    let mut strip_off = 0;
    for (i, byte) in bytes.iter().rev().enumerate() {
        if *byte == NEWLINE_SLASH_N || *byte == NEWLINE_SLASH_R {
            strip_off = i + 1;
        } else {
            break;
        }
    }
    bytes.resize(bytes.len() - strip_off, 0);

    bytes.to_vec()
}

#[cfg(test)]
mod test {
    use super::strip_off_newline_codes;

    #[test]
    fn test_strip_off() {
        let expected_bytes: Vec<u8> = vec![108, 105, 103, 104, 116, 104, 111, 117, 115, 101];

        let mut bytes: Vec<u8> = vec![108, 105, 103, 104, 116, 104, 111, 117, 115, 101, 10];
        bytes = strip_off_newline_codes(&mut bytes);
        assert_eq!(bytes, expected_bytes);

        let mut bytes: Vec<u8> = vec![
            108, 105, 103, 104, 116, 104, 111, 117, 115, 101, 10, 10, 10, 10,
        ];
        bytes = strip_off_newline_codes(&mut bytes);
        assert_eq!(bytes, expected_bytes);

        let mut bytes: Vec<u8> = vec![108, 105, 103, 104, 116, 104, 111, 117, 115, 101, 13];
        bytes = strip_off_newline_codes(&mut bytes);
        assert_eq!(bytes, expected_bytes);

        let mut bytes: Vec<u8> = vec![
            108, 105, 103, 104, 116, 104, 111, 117, 115, 101, 13, 13, 13, 13, 13, 13,
        ];
        bytes = strip_off_newline_codes(&mut bytes);
        assert_eq!(bytes, expected_bytes);

        let mut bytes: Vec<u8> = vec![108, 105, 103, 104, 116, 104, 111, 117, 115, 101, 13, 10];
        bytes = strip_off_newline_codes(&mut bytes);
        assert_eq!(bytes, expected_bytes);

        let mut bytes: Vec<u8> = vec![
            108, 105, 103, 104, 116, 104, 111, 117, 115, 101, 13, 10, 13, 10, 13, 10,
        ];
        bytes = strip_off_newline_codes(&mut bytes);
        assert_eq!(bytes, expected_bytes);

        let mut bytes: Vec<u8> = vec![108, 105, 103, 104, 116, 104, 111, 117, 115, 101];
        bytes = strip_off_newline_codes(&mut bytes);
        assert_eq!(bytes, expected_bytes);
    }
}
