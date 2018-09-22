use super::utils::types::{ Hash256, Bitfield };
use super::utils::bls::{ AggregateSignature };
use super::ssz::{
    Encodable,
    Decodable,
    DecodeError,
    decode_ssz_list,
    SszStream,
};

pub const MIN_SSZ_ATTESTION_RECORD_LENGTH: usize = {
    8 +             // slot
    2 +             // shard_id
    4 +             // oblique_parent_hashes (empty list)
    32 +            // shard_block_hash
    5 +             // attester_bitfield (assuming 1 byte of bitfield)
    8 +             // justified_slot
    32 +            // justified_block_hash
    4 + (2 * 8)    // aggregate sig (two 256 bit points)
};

#[derive(Debug)]
pub struct AttestationRecord {
    pub slot: u64,
    pub shard_id: u16,
    pub oblique_parent_hashes: Vec<Hash256>,
    pub shard_block_hash: Hash256,
    pub attester_bitfield: Bitfield,
    pub justified_slot: u64,
    pub justified_block_hash: Hash256,
    pub aggregate_sig: Option<AggregateSignature>,
}

impl Encodable for AttestationRecord {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slot);
        s.append(&self.shard_id);
        s.append_vec(&self.oblique_parent_hashes);
        s.append(&self.shard_block_hash);
        s.append_vec(&self.attester_bitfield.to_be_vec());
        s.append(&self.justified_slot);
        s.append(&self.justified_block_hash);
        // TODO: encode the aggregate sig correctly
        s.append_vec(&vec![0_u8; 16])
    }
}

impl Decodable for AttestationRecord {
    fn ssz_decode(bytes: &[u8], i: usize)
        -> Result<(Self, usize), DecodeError>
    {
        let (slot, i) = u64::ssz_decode(bytes, i)?;
        let (shard_id, i) = u16::ssz_decode(bytes, i)?;
        let (oblique_parent_hashes, i) = decode_ssz_list(bytes, i)?;
        let (shard_block_hash, i) = Hash256::ssz_decode(bytes, i)?;
        let (attester_bitfield, i) = Bitfield::ssz_decode(bytes, i)?;
        let (justified_slot, i) = u64::ssz_decode(bytes, i)?;
        let (justified_block_hash, i) = Hash256::ssz_decode(bytes, i)?;
        // Do aggregate sig decoding properly.
        let aggregate_sig = None; let i = i + 20;
        let attestation_record = Self {
            slot,
            shard_id,
            oblique_parent_hashes,
            shard_block_hash,
            attester_bitfield,
            justified_slot,
            justified_block_hash,
            aggregate_sig,
        };
        Ok((attestation_record, i))
    }
}

impl AttestationRecord {
    pub fn zero() -> Self {
        Self {
            slot: 0,
            shard_id: 0,
            oblique_parent_hashes: vec![],
            shard_block_hash: Hash256::zero(),
            attester_bitfield: Bitfield::new(),
            justified_slot: 0,
            justified_block_hash: Hash256::zero(),
            aggregate_sig: None,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ssz::SszStream;

    #[test]
    pub fn test_attestation_record_min_ssz_length() {
        let ar = AttestationRecord::zero();
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&ar);
        let ssz = ssz_stream.drain();

        assert_eq!(ssz.len(), MIN_SSZ_ATTESTION_RECORD_LENGTH);
    }

    #[test]
    pub fn test_attestation_record_min_ssz_encode_decode() {
        let original = AttestationRecord {
            slot: 7,
            shard_id: 9,
            oblique_parent_hashes: vec![Hash256::from(&vec![14; 32][..])],
            shard_block_hash: Hash256::from(&vec![15; 32][..]),
            attester_bitfield: Bitfield::from(&vec![17; 42][..]),
            justified_slot: 19,
            justified_block_hash: Hash256::from(&vec![15; 32][..]),
            aggregate_sig: None,
        };

        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&original);

        let (decoded, _) = AttestationRecord::
            ssz_decode(&ssz_stream.drain(), 0).unwrap();
        assert_eq!(original.slot, decoded.slot);
        assert_eq!(original.shard_id, decoded.shard_id);
        assert_eq!(original.oblique_parent_hashes, decoded.oblique_parent_hashes);
        assert_eq!(original.shard_block_hash, decoded.shard_block_hash);
        assert_eq!(original.attester_bitfield, decoded.attester_bitfield);
        assert_eq!(original.justified_slot, decoded.justified_slot);
        assert_eq!(original.justified_block_hash, decoded.justified_block_hash);
    }
}
