use super::types::attestation_record::MIN_SSZ_ATTESTION_RECORD_LENGTH as MIN_LENGTH;
use super::ssz::LENGTH_BYTES;
use super::ssz::decode::decode_length;

#[derive(Debug, PartialEq)]
pub enum AttestationSplitError {
    TooShort,
}

/// Given some ssz slice, find the bounds of each serialized AttestationRecord and return a vec of
/// slices point to each.
pub fn split_all_attestations<'a>(full_ssz: &'a [u8], index: usize)
    -> Result<Vec<&'a [u8]>, AttestationSplitError>
{
    let mut v = vec![];
    let mut index = index;
    while index < full_ssz.len() - 1 {
        let (slice, i) = split_one_attestation(full_ssz, index)?;
        v.push(slice);
        index = i;
    }
    Ok(v)
}

/// Given some ssz slice, find the bounds of one serialized AttestationRecord
/// and return a slice pointing to that.
pub fn split_one_attestation(full_ssz: &[u8], index: usize)
    -> Result<(&[u8], usize), AttestationSplitError>
{
    if full_ssz.len() < MIN_LENGTH {
        return Err(AttestationSplitError::TooShort);
    }

    let hashes_len = decode_length(full_ssz, index + 10, LENGTH_BYTES)
        .map_err(|_| AttestationSplitError::TooShort)?;

    let bitfield_len = decode_length(
        full_ssz, index + hashes_len + 46,
        LENGTH_BYTES)
        .map_err(|_| AttestationSplitError::TooShort)?;

    // Subtract one because the min length assumes 1 byte of bitfield
    let len = MIN_LENGTH - 1
        + hashes_len
        + bitfield_len;

    if full_ssz.len() < index + len {
        return Err(AttestationSplitError::TooShort);
    }

    Ok((&full_ssz[index..(index + len)], index + len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::{
        AttestationRecord,
        Hash256,
        Bitfield,
    };
    use super::super::bls::AggregateSignature;
    use super::super::ssz::{
        SszStream,
        Decodable,
    };

    fn get_two_records() -> Vec<AttestationRecord> {
        let a = AttestationRecord {
            slot: 7,
            shard_id: 9,
            oblique_parent_hashes: vec![Hash256::from(&vec![14; 32][..])],
            shard_block_hash: Hash256::from(&vec![15; 32][..]),
            attester_bitfield: Bitfield::from(&vec![17; 42][..]),
            justified_slot: 19,
            justified_block_hash: Hash256::from(&vec![15; 32][..]),
            aggregate_sig: AggregateSignature::new(),
        };
        let b = AttestationRecord {
            slot: 9,
            shard_id: 7,
            oblique_parent_hashes: vec![Hash256::from(&vec![15; 32][..])],
            shard_block_hash: Hash256::from(&vec![14; 32][..]),
            attester_bitfield: Bitfield::from(&vec![19; 42][..]),
            justified_slot: 15,
            justified_block_hash: Hash256::from(&vec![17; 32][..]),
            aggregate_sig: AggregateSignature::new(),
        };
        vec![a, b]
    }

    #[test]
    fn test_attestation_ssz_split() {
        let ars = get_two_records();
        let a = ars[0].clone();
        let b = ars[1].clone();


        /*
         * Test split one
         */
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&a);
        let ssz = ssz_stream.drain();
        let (a_ssz, i) = split_one_attestation(&ssz, 0).unwrap();
        assert_eq!(i, ssz.len());
        let (decoded_a, _) = AttestationRecord::ssz_decode(a_ssz, 0)
            .unwrap();
        assert_eq!(a, decoded_a);

        /*
         * Test split two
         */
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&a);
        ssz_stream.append(&b);
        let ssz = ssz_stream.drain();
        let ssz_vec = split_all_attestations(&ssz, 0).unwrap();
        let (decoded_a, _) =
            AttestationRecord::ssz_decode(ssz_vec[0], 0)
            .unwrap();
        let (decoded_b, _) =
            AttestationRecord::ssz_decode(ssz_vec[1], 0)
            .unwrap();
        assert_eq!(a, decoded_a);
        assert_eq!(b, decoded_b);

        /*
         * Test split two with shortened ssz
         */
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&a);
        ssz_stream.append(&b);
        let ssz = ssz_stream.drain();
        let ssz = &ssz[0..ssz.len() - 1];
        assert!(split_all_attestations(&ssz, 0).is_err());
    }
}

