use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::ProposalSignedData;
use bls::Signature;

#[derive(Debug, PartialEq, Clone, Default)]
pub struct ProposerSlashing {
    pub proposer_index: u32,
    pub proposal_data_1: ProposalSignedData,
    pub proposal_signature_1: Signature,
    pub proposal_data_2: ProposalSignedData,
    pub proposal_signature_2: Signature,
}

impl Encodable for ProposerSlashing {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.proposer_index);
        s.append(&self.proposal_data_1);
        s.append(&self.proposal_signature_1);
        s.append(&self.proposal_data_2);
        s.append(&self.proposal_signature_2);
    }
}

impl Decodable for ProposerSlashing {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (proposer_index, i) = u32::ssz_decode(bytes, i)?;
        let (proposal_data_1, i) = ProposalSignedData::ssz_decode(bytes, i)?;
        let (proposal_signature_1, i) = Signature::ssz_decode(bytes, i)?;
        let (proposal_data_2, i) = ProposalSignedData::ssz_decode(bytes, i)?;
        let (proposal_signature_2, i) = Signature::ssz_decode(bytes, i)?;

        Ok((
            ProposerSlashing {
                proposer_index,
                proposal_data_1,
                proposal_signature_1,
                proposal_data_2,
                proposal_signature_2,
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

        let original = ProposerSlashing {
            proposer_index: 42,
            proposal_data_1: ProposalSignedData {
                slot: 45,
                shard: 110,
                block_root: Hash256::from("cats".as_bytes()),
            },
            proposal_signature_1: Signature::new(&[42, 42], &keypair.sk),
            proposal_data_2: ProposalSignedData {
                slot: 1,
                shard: 260,
                block_root: Hash256::from("lol".as_bytes()),
            },
            proposal_signature_2: Signature::new(&[7, 8], &keypair.sk),
        };

        let bytes = ssz_encode(&original);
        let (decoded, _) = ProposerSlashing::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
