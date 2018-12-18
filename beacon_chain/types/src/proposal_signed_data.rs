use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::Hash256;

#[derive(Debug, PartialEq, Clone, Default)]
pub struct ProposalSignedData {
    pub slot: u64,
    pub shard: u64,
    pub block_root: Hash256,
}

impl Encodable for ProposalSignedData {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.shard);
        s.append(&self.block_root);
    }
}

impl Decodable for ProposalSignedData {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slot, i) = u64::ssz_decode(bytes, i)?;
        let (shard, i) = u64::ssz_decode(bytes, i)?;
        let (block_root, i) = Hash256::ssz_decode(bytes, i)?;

        Ok((
            ProposalSignedData {
                slot,
                shard,
                block_root,
            },
            i,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;

    #[test]
    pub fn test_ssz_round_trip() {
        let original = ProposalSignedData {
            slot: 42,
            shard: 120,
            block_root: Hash256::from("cats".as_bytes()),
        };

        let bytes = ssz_encode(&original);
        let (decoded, _) = ProposalSignedData::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
