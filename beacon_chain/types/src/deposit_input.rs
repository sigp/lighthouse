use super::ssz::{decode_ssz_list, Decodable, DecodeError, Encodable, SszStream};
use super::Hash256;
use bls::{PublicKey, Signature};

#[derive(Debug, PartialEq, Clone)]
pub struct DepositInput {
    pub pubkey: PublicKey,
    pub withdrawal_credentials: Hash256,
    pub randao_commitment: Hash256,
    pub proof_of_possession: Signature,
}

impl Encodable for DepositInput {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.pubkey.as_bytes());
        s.append(&self.withdrawal_credentials);
        s.append(&self.randao_commitment);
        s.append(&self.proof_of_possession);
    }
}

impl Decodable for DepositInput {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (pubkey_bytes, i) = decode_ssz_list(bytes, i)?;
        let pubkey = PublicKey::from_bytes(&pubkey_bytes).map_err(|_| DecodeError::TooShort)?;
        let (withdrawal_credentials, i) = <_>::ssz_decode(bytes, i)?;
        let (randao_commitment, i) = <_>::ssz_decode(bytes, i)?;
        let (proof_of_possession, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            Self {
                pubkey,
                withdrawal_credentials,
                randao_commitment,
                proof_of_possession,
            },
            i,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;
    use bls::{Keypair, Signature};

    #[test]
    pub fn test_ssz_round_trip() {
        let keypair = Keypair::random();

        let original = DepositInput {
            pubkey: keypair.pk,
            withdrawal_credentials: Hash256::from("cats".as_bytes()),
            randao_commitment: Hash256::from("dogs".as_bytes()),
            proof_of_possession: Signature::new(&[42, 42], &keypair.sk),
        };

        let bytes = ssz_encode(&original);
        let (decoded, _) = DepositInput::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
