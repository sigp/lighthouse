use super::{AggregatePublicKey, Signature};
use bls_aggregates::{
    AggregatePublicKey as RawAggregatePublicKey, AggregateSignature as RawAggregateSignature,
};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use serde_hex::{encode as hex_encode, PrefixedHexVisitor};
use ssz::{
    decode_ssz_list, hash, ssz_encode, Decodable, DecodeError, Encodable, SszStream, TreeHash,
};

/// A BLS aggregate signature.
///
/// This struct is a wrapper upon a base type and provides helper functions (e.g., SSZ
/// serialization).
#[derive(Debug, PartialEq, Clone, Default, Eq)]
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
    pub fn verify(
        &self,
        msg: &[u8],
        domain: u64,
        aggregate_public_key: &AggregatePublicKey,
    ) -> bool {
        self.0.verify(msg, domain, aggregate_public_key.as_raw())
    }

    /// Verify this AggregateSignature against multiple AggregatePublickeys with multiple Messages.
    ///
    ///  All PublicKeys related to a Message should be aggregated into one AggregatePublicKey.
    ///  Each AggregatePublicKey has a 1:1 ratio with a 32 byte Message.
    pub fn verify_multiple(
        &self,
        messages: &[&[u8]],
        domain: u64,
        aggregate_public_keys: &[&AggregatePublicKey],
    ) -> bool {
        let aggregate_public_keys: Vec<&RawAggregatePublicKey> =
            aggregate_public_keys.iter().map(|pk| pk.as_raw()).collect();

        // Messages are concatenated into one long message.
        let mut msg: Vec<u8> = vec![];
        for message in messages {
            msg.extend_from_slice(message);
        }

        self.0
            .verify_multiple(&msg[..], domain, &aggregate_public_keys[..])
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

impl Serialize for AggregateSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex_encode(ssz_encode(self)))
    }
}

impl<'de> Deserialize<'de> for AggregateSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = deserializer.deserialize_str(PrefixedHexVisitor)?;
        let (obj, _) = <_>::ssz_decode(&bytes[..], 0)
            .map_err(|e| serde::de::Error::custom(format!("invalid ssz ({:?})", e)))?;
        Ok(obj)
    }
}

impl TreeHash for AggregateSignature {
    fn hash_tree_root(&self) -> Vec<u8> {
        hash(&self.0.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Keypair, Signature};
    use super::*;
    use ssz::ssz_encode;

    #[test]
    pub fn test_ssz_round_trip() {
        let keypair = Keypair::random();

        let mut original = AggregateSignature::new();
        original.add(&Signature::new(&[42, 42], 0, &keypair.sk));

        let bytes = ssz_encode(&original);
        let (decoded, _) = AggregateSignature::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
