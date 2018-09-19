use super::utils::types::{ Hash256, Bitfield };
use super::utils::bls::{ AggregateSignature };
use super::ssz::{ Encodable, SszStream };

pub const MIN_SSZ_ATTESTION_RECORD_LENGTH: usize = {
    8 +             // slot
    2 +             // shard_id
    4 +             // oblique_parent_hashes (empty list)
    4 + 32 +        // shard_block_hash
    5 +             // attester_bitfield (assuming 1 byte of bitfield)
    8 +             // justified_slot
    4 + 32 +        // justified_block_hash
    4 + (2 * 32)    // aggregate sig (two 256 bit points)
};

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
        s.append_vec(&vec![0_u8; 64])
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
}
