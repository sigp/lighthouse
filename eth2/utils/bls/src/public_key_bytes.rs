use ssz::{Decode, DecodeError, Encode};

use super::{PublicKey, BLS_PUBLIC_KEY_BYTE_SIZE};

bytes_struct!(
    PublicKeyBytes,
    PublicKey,
    BLS_PUBLIC_KEY_BYTE_SIZE,
    "public key",
    U48
);

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use ssz::ssz_encode;

    use super::super::Keypair;
    use super::*;

    #[test]
    pub fn test_valid_public_key() {
        let keypair = Keypair::random();

        let bytes = ssz_encode(&keypair.pk);
        let public_key_bytes = PublicKeyBytes::from_bytes(&bytes).unwrap();
        let public_key: Result<PublicKey, _> = (&public_key_bytes).try_into();
        assert!(public_key.is_ok());
        assert_eq!(keypair.pk, public_key.unwrap());
    }

    #[test]
    #[cfg(not(feature = "fake_crypto"))]
    pub fn test_invalid_public_key() {
        let mut public_key_bytes = [0; BLS_PUBLIC_KEY_BYTE_SIZE];
        public_key_bytes[0] = 255; //a_flag1 == b_flag1 == c_flag1 == 1 and x1 = 0 shouldn't be allowed
        let public_key_bytes = PublicKeyBytes::from_bytes(&public_key_bytes[..]);
        assert!(public_key_bytes.is_ok());

        let public_key: Result<PublicKey, _> = public_key_bytes.as_ref().unwrap().try_into();
        assert!(public_key.is_err());
    }
}
