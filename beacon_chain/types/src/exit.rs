use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use bls::AggregateSignature;

#[derive(Debug, PartialEq, Clone)]
pub struct Exit {
    pub slot: u64,
    pub validator_index: u32,
    pub signature: AggregateSignature,
}

impl Encodable for Exit {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.validator_index);
        s.append(&self.signature);
    }
}

impl Decodable for Exit {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = <_>::ssz_decode(bytes, i)?;
        let (validator_index, i) = <_>::ssz_decode(bytes, i)?;
        let (signature, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                slot,
                validator_index,
                signature,
            },
            i,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;
    use bls::{AggregateSignature, Keypair, Signature};

    #[test]
    pub fn test_ssz_round_trip() {
        let keypair = Keypair::random();
        let single_signature = Signature::new(&[42, 42], &keypair.sk);
        let mut signature = AggregateSignature::new();
        signature.add(&single_signature);

        let original = Exit {
            slot: 42,
            validator_index: 12,
            signature,
        };

        let bytes = ssz_encode(&original);
        let (decoded, _) = Exit::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
