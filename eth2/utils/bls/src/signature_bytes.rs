use ssz::{Decode, DecodeError, Encode};

use super::{Signature, BLS_SIG_BYTE_SIZE};

bytes_struct!(
    SignatureBytes,
    Signature,
    BLS_SIG_BYTE_SIZE,
    "signature",
    U96
);

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use ssz::ssz_encode;

    use super::super::Keypair;
    use super::*;

    #[test]
    pub fn test_valid_signature() {
        let keypair = Keypair::random();
        let original = Signature::new(&[42, 42], 0, &keypair.sk);

        let bytes = ssz_encode(&original);
        let signature_bytes = SignatureBytes::from_bytes(&bytes).unwrap();
        let signature: Result<Signature, _> = (&signature_bytes).try_into();
        assert!(signature.is_ok());
        assert_eq!(original, signature.unwrap());
    }

    #[test]
    #[cfg(not(feature = "fake_crypto"))]
    pub fn test_invalid_signature() {
        let mut signature_bytes = [0; BLS_SIG_BYTE_SIZE];
        signature_bytes[0] = 255; //a_flag1 == b_flag1 == c_flag1 == 1 and x1 = 0 shouldn't be allowed
        let signature_bytes = SignatureBytes::from_bytes(&signature_bytes[..]);
        assert!(signature_bytes.is_ok());

        let signature: Result<Signature, _> = signature_bytes.as_ref().unwrap().try_into();
        assert!(signature.is_err());
    }
}
