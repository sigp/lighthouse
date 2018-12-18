use super::ssz::{decode_ssz_list, Decodable, DecodeError, Encodable, SszStream};
use super::{AggregatePublicKey, Signature};
use bls_aggregates::AggregateSignature as RawAggregateSignature;

/// A BLS aggregate signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone)]
pub struct AggregateSignature(RawAggregateSignature);

impl AggregateSignature {
    /// Instantiate a new AggregateSignature.
    pub fn new() -> Self {
        AggregateSignature(RawAggregateSignature::new())
    }

    /// Add (aggregate) a signature to the `AggregateSignature`.
    pub fn add(&mut self, signature: &Signature) {
        self.0.add(signature.as_raw())
    }

    /// Verify the `AggregateSignature` against an `AggregatePublicKey`.
    ///
    /// Only returns `true` if the set of keys in the `AggregatePublicKey` match the set of keys
    /// that signed the `AggregateSignature`.
    pub fn verify(&self, msg: &[u8], avk: &AggregatePublicKey) -> bool {
        self.0.verify(msg, avk)
    }
}

impl Default for AggregateSignature {
    /// A "default" signature is a signature across an empty message by a secret key of 48 zeros.
    fn default() -> Self {
        AggregateSignature::new()
    }
}

impl Encodable for AggregateSignature {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.0.as_bytes());
    }
}

impl Decodable for AggregateSignature {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (sig_bytes, i) = decode_ssz_list(bytes, i)?;
        let raw_sig =
            RawAggregateSignature::from_bytes(&sig_bytes).map_err(|_| DecodeError::TooShort)?;
        Ok((AggregateSignature(raw_sig), i))
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::super::{Keypair, Signature};
    use super::*;

    #[test]
    pub fn test_ssz_round_trip() {
        let keypair = Keypair::random();

        let mut original = AggregateSignature::new();
        original.add(&Signature::new(&[42, 42], &keypair.sk));

        let bytes = ssz_encode(&original);
        let (decoded, _) = AggregateSignature::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
