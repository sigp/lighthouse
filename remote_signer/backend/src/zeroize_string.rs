use bls::SecretKey;
use std::str;
use zeroize::Zeroize;

/// Provides a new-type wrapper around `String` that is zeroized on `Drop`.
///
/// Useful for ensuring that secret key memory is zeroed-out on drop.
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
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

impl ZeroizeString {
    /// Consumes the ZeroizeString, attempting to return a BLS SecretKey.
    pub fn into_bls_sk(self) -> Result<SecretKey, String> {
        let mut decoded_bytes = hex_string_to_bytes(&self.0)?;

        let secret_key = SecretKey::deserialize(&decoded_bytes).map_err(|e| format!("{:?}", e))?;
        decoded_bytes.zeroize();

        Ok(secret_key)
    }
}

// An alternative to `hex::decode`, to allow for more control of
// the objects created while decoding the secret key.
fn hex_string_to_bytes(data: &str) -> Result<Vec<u8>, String> {
    if data.len() % 2 != 0 {
        return Err("Odd length".to_string());
    }

    let mut vec: Vec<u8> = Vec::new();
    for i in 0..data.len() / 2 {
        vec.push(
            val(&data.as_bytes()[2 * i], 2 * i)? << 4
                | val(&data.as_bytes()[2 * i + 1], 2 * i + 1)?,
        );
    }

    Ok(vec)
}

// Auxiliar function for `hex_string_to_bytes`.
fn val(c: &u8, idx: usize) -> Result<u8, String> {
    match c {
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'0'..=b'9' => Ok(c - b'0'),
        _ => Err(format!(
            "Invalid hex character: {} at index {}",
            *c as char, idx
        )),
    }
}

#[cfg(test)]
mod object {
    use super::*;
    use helpers::*;
    use zeroize::Zeroize;

    #[test]
    fn v_u8_zeroized() {
        // Create from `hex_string_to_bytes`, and record the pointer to its buffer.
        let mut decoded_bytes = hex_string_to_bytes(SECRET_KEY_1).unwrap();
        let old_pointer = decoded_bytes.as_ptr() as usize;

        // Do something with the borrowed vector, and zeroize.
        let _ = SecretKey::deserialize(&decoded_bytes)
            .map_err(|e| format!("{:?}", e))
            .unwrap();
        decoded_bytes.zeroize();

        // Check it is pointing to the same buffer, and that it was deleted.
        assert_eq!(old_pointer as usize, decoded_bytes.as_ptr() as usize);
        assert!(decoded_bytes.is_empty());

        // Check if the underlying bytes were zeroized.
        for i in 0..SECRET_KEY_1.len() / 2 {
            unsafe {
                assert_eq!(*((old_pointer + i) as *const u8), 0);
            }
        }
    }

    #[test]
    fn fn_to_bls_sk() {
        let test_ok_case = |sk: &str, sk_b: &[u8]| {
            let z = ZeroizeString::from(sk.to_string());
            let sk: SecretKey = z.into_bls_sk().unwrap();
            assert_eq!(sk.serialize().as_bytes(), sk_b);
        };

        let test_error_case = |sk: &str, err_msg: &str| {
            let z = ZeroizeString::from(sk.to_string());
            let err = z.into_bls_sk().err();
            assert_eq!(err, Some(err_msg.to_string()));
        };

        test_ok_case(SECRET_KEY_1, &SECRET_KEY_1_BYTES);

        test_error_case("Trolololololo", "Odd length");
        test_error_case("Trololololol", "Invalid hex character: T at index 0");
        test_error_case(
            "そんなことないでしょうけどう",
            "Invalid hex character: ã at index 0",
        );
    }

    #[test]
    fn zeroized_after_drop() {
        let some_scope = |s: &str| -> usize {
            // Convert our literal into a String, then store the pointer
            // to the first byte of its slice.
            let s: String = s.to_string();
            let s_ptr = s.as_ptr();

            // Just to make sure that the pointer of the string is NOT
            // the same as the pointer of the underlying buffer.
            assert_ne!(&s as *const String as usize, s_ptr as usize);

            let z = ZeroizeString::from(s);

            // Get the pointer to the underlying buffer,
            // We want to make sure is the same as the received string literal.
            // That is, no copies of the contents.
            let ptr_to_buf = z.as_ref().as_ptr();
            assert_eq!(ptr_to_buf, s_ptr);

            // We exit this scope, returning to the caller the pointer to
            // the buffer, that we'll use to verify the zeroization.
            ptr_to_buf as usize
        };

        // Call the closure.
        let ptr_to_buf = some_scope(SECRET_KEY_1);

        // Check if the underlying bytes were zeroized.
        // At this point the first half is already reclaimed and assigned,
        // so we will just examine the other half.
        for i in SECRET_KEY_1.len() / 2..SECRET_KEY_1.len() {
            unsafe {
                assert_eq!(*((ptr_to_buf + i) as *const u8), 0);
            }
        }
    }
}

#[cfg(test)]
mod functions {
    use super::*;
    use helpers::*;

    #[test]
    fn fn_hex_string_to_bytes() {
        assert_eq!(
            hex_string_to_bytes(&"0aa".to_string()).err(),
            Some("Odd length".to_string())
        );

        assert_eq!(
            hex_string_to_bytes(&"0xdeadbeef".to_string()).err(),
            Some("Invalid hex character: x at index 1".to_string())
        );

        assert_eq!(
            hex_string_to_bytes(&"n00bn00b".to_string()).err(),
            Some("Invalid hex character: n at index 0".to_string())
        );

        assert_eq!(
            hex_string_to_bytes(&"abcdefgh".to_string()).err(),
            Some("Invalid hex character: g at index 6".to_string())
        );

        assert_eq!(
            hex_string_to_bytes(SECRET_KEY_1).unwrap(),
            SECRET_KEY_1_BYTES
        );

        assert_eq!(
            hex_string_to_bytes(PUBLIC_KEY_1).unwrap(),
            PUBLIC_KEY_1_BYTES.to_vec()
        );

        assert_eq!(
            hex_string_to_bytes(SIGNING_ROOT).unwrap(),
            SIGNING_ROOT_BYTES.to_vec()
        );

        assert_eq!(
            hex_string_to_bytes(&EXPECTED_SIGNATURE_1[2..]).unwrap(),
            EXPECTED_SIGNATURE_1_BYTES.to_vec()
        );

        assert_eq!(
            hex_string_to_bytes(&EXPECTED_SIGNATURE_2[2..]).unwrap(),
            EXPECTED_SIGNATURE_2_BYTES.to_vec()
        );

        assert_eq!(
            hex_string_to_bytes(&EXPECTED_SIGNATURE_3[2..]).unwrap(),
            EXPECTED_SIGNATURE_3_BYTES.to_vec()
        );

        assert_eq!(
            hex_string_to_bytes(&"0a0b11".to_string()).unwrap(),
            vec![10, 11, 17]
        );
    }
}
