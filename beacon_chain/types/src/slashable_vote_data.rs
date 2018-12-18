use super::ssz::{decode_ssz_list, Decodable, DecodeError, Encodable, SszStream};
use super::AttestationData;
use bls::AggregateSignature;

#[derive(Debug, PartialEq, Clone, Default)]
pub struct SlashableVoteData {
    pub aggregate_signature_poc_0_indices: Vec<u32>,
    pub aggregate_signature_poc_1_indices: Vec<u32>,
    pub data: AttestationData,
    pub aggregate_signature: AggregateSignature,
}

impl Encodable for SlashableVoteData {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.aggregate_signature_poc_0_indices);
        s.append_vec(&self.aggregate_signature_poc_1_indices);
        s.append(&self.data);
        s.append(&self.aggregate_signature);
    }
}

impl Decodable for SlashableVoteData {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (aggregate_signature_poc_0_indices, i) = decode_ssz_list(bytes, i)?;
        let (aggregate_signature_poc_1_indices, i) = decode_ssz_list(bytes, i)?;
        let (data, i) = AttestationData::ssz_decode(bytes, i)?;
        let (aggregate_signature, i) = AggregateSignature::ssz_decode(bytes, i)?;

        Ok((
            SlashableVoteData {
                aggregate_signature_poc_0_indices,
                aggregate_signature_poc_1_indices,
                data,
                aggregate_signature,
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

    #[test]
    pub fn test_ssz_round_trip() {
        let original = SlashableVoteData {
            aggregate_signature_poc_0_indices: vec![0, 1, 2],
            aggregate_signature_poc_1_indices: vec![42, 42, 42],
            data: AttestationData {
                slot: 42,
                shard: 16,
                beacon_block_hash: Hash256::from("beacon".as_bytes()),
                epoch_boundary_hash: Hash256::from("epoch".as_bytes()),
                shard_block_hash: Hash256::from("shard".as_bytes()),
                latest_crosslink_hash: Hash256::from("xlink".as_bytes()),
                justified_slot: 8,
                justified_block_hash: Hash256::from("justified".as_bytes()),
            },
            aggregate_signature: AggregateSignature::new(),
        };

        let bytes = ssz_encode(&original);
        let (decoded, _) = SlashableVoteData::ssz_decode(&bytes, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
