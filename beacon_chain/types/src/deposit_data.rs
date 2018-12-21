use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::DepositInput;

#[derive(Debug, PartialEq, Clone)]
pub struct DepositData {
    pub deposit_input: DepositInput,
    pub value: u64,
    pub timestamp: u64,
}

impl Encodable for DepositData {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.deposit_input);
        s.append(&self.value);
        s.append(&self.timestamp);
    }
}

impl Decodable for DepositData {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (deposit_input, i) = <_>::ssz_decode(bytes, i)?;
        let (value, i) = <_>::ssz_decode(bytes, i)?;
        let (timestamp, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                deposit_input,
                value,
                timestamp,
            },
            i,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::super::Hash256;
    use super::*;
    use bls::{Keypair, Signature};

    #[test]
    pub fn test_ssz_round_trip() {
        let keypair = Keypair::random();

        let original = DepositData {
            deposit_input: DepositInput {
                pubkey: keypair.pk,
                withdrawal_credentials: Hash256::from("cats".as_bytes()),
                randao_commitment: Hash256::from("dogs".as_bytes()),
                proof_of_possession: Signature::new(&[42, 42], &keypair.sk),
            },
            value: 12,
            timestamp: 100,
        };

        let bytes = ssz_encode(&original);
        let (decoded, _) = DepositData::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
