use crate::{BackendError, ZeroizeString};
use bls::SecretKey;
use hex::decode;
use std::fmt::{Error, Write};
use std::str;

// hex::encode only allows up to 32 bytes.
pub fn bytes96_to_hex_string(data: [u8; 96]) -> Result<String, Error> {
    static CHARS: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(96 * 2 + 2);

    s.write_char('0')?;
    s.write_char('x')?;

    for &byte in data.iter() {
        s.write_char(CHARS[(byte >> 4) as usize].into())?;
        s.write_char(CHARS[(byte & 0xf) as usize].into())?;
    }

    Ok(s)
}

/// Validates the match as a BLS pair of the public and secret keys given,
/// consuming the secret key parameter, and returning a deserialized SecretKey.
pub fn validate_bls_pair(
    public_key: &str,
    secret_key: ZeroizeString,
) -> Result<SecretKey, BackendError> {
    let secret_key: SecretKey = secret_key.into_bls_sk().map_err(|e| {
        BackendError::InvalidSecretKey(format!("public_key: {}; {}", public_key, e))
    })?;

    let pk_param_as_bytes = decode(&public_key)
        .map_err(|e| BackendError::InvalidPublicKey(format!("{}; {}", public_key, e)))?;

    if &secret_key.public_key().serialize()[..] != pk_param_as_bytes.as_slice() {
        return Err(BackendError::KeyMismatch(public_key.to_string()));
    }

    Ok(secret_key)
}

#[cfg(test)]
mod functions {
    use super::*;
    use helpers::*;

    #[test]
    fn fn_bytes96_to_hex_string() {
        assert_eq!(
            bytes96_to_hex_string(EXPECTED_SIGNATURE_1_BYTES).unwrap(),
            EXPECTED_SIGNATURE_1
        );

        assert_eq!(
            bytes96_to_hex_string(EXPECTED_SIGNATURE_2_BYTES).unwrap(),
            EXPECTED_SIGNATURE_2
        );

        assert_eq!(
            bytes96_to_hex_string(EXPECTED_SIGNATURE_3_BYTES).unwrap(),
            EXPECTED_SIGNATURE_3
        );
    }

    #[test]
    fn fn_validate_bls_pair() {
        let test_ok_case = |pk: &str, sk: ZeroizeString, sk_bytes: &[u8; 32]| {
            let serialized_secret_key = validate_bls_pair(pk, sk).unwrap().serialize();
            assert_eq!(serialized_secret_key.as_bytes().to_vec(), sk_bytes.to_vec());
        };

        test_ok_case(
            PUBLIC_KEY_1,
            ZeroizeString::from(SECRET_KEY_1.to_string()),
            &SECRET_KEY_1_BYTES,
        );

        let test_error_case = |pk: &str, sk: ZeroizeString, expected_error: &str| {
            assert_eq!(
                validate_bls_pair(pk, sk).err().unwrap().to_string(),
                expected_error
            );
        };

        test_error_case(
            PUBLIC_KEY_2,
            ZeroizeString::from("TamperedKey%#$#%#$$&##00£$%$$£%$".to_string()),
            &format!(
                "Invalid secret key: public_key: {}; Invalid hex character: T at index 0",
                PUBLIC_KEY_2
            ),
        );

        test_error_case(
            PUBLIC_KEY_2,
            ZeroizeString::from("deadbeef".to_string()),
            &format!(
                "Invalid secret key: public_key: {}; InvalidSecretKeyLength {{ got: 4, expected: 32 }}",
                PUBLIC_KEY_2
            ),
        );

        let bad_pk_param = "not_validated_by_the_api_handler!";
        test_error_case(
            bad_pk_param,
            ZeroizeString::from(SECRET_KEY_1.to_string()),
            &format!("Invalid public key: {}; Odd number of digits", bad_pk_param),
        );

        test_error_case(
            PUBLIC_KEY_1,
            ZeroizeString::from(SECRET_KEY_2.to_string()),
            &format!("Key mismatch: {}", PUBLIC_KEY_1),
        );

        test_error_case(
            PUBLIC_KEY_2,
            ZeroizeString::from(SECRET_KEY_3.to_string()),
            &format!("Key mismatch: {}", PUBLIC_KEY_2),
        );
    }
}
