use super::bls::BLS_AGG_SIG_BYTE_SIZE;
use super::ssz::decode::decode_length;
use super::ssz::LENGTH_BYTES;
use super::types::attestation_data::SSZ_ATTESTION_DATA_LENGTH;
use super::types::attestation_record::MIN_SSZ_ATTESTION_RECORD_LENGTH;

#[derive(Debug, PartialEq)]
pub enum AttestationSplitError {
    TooShort,
}

/// Given some ssz slice, find the bounds of each serialized AttestationRecord and return a vec of
/// slices point to each.
pub fn split_all_attestations<'a>(
    full_ssz: &'a [u8],
    index: usize,
) -> Result<Vec<&'a [u8]>, AttestationSplitError> {
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
pub fn split_one_attestation(
    full_ssz: &[u8],
    index: usize,
) -> Result<(&[u8], usize), AttestationSplitError> {
    let length = determine_ssz_attestation_len(full_ssz, index)?;
    let end = index + length;

    // The check to ensure that the slice exists _should_ be redundant as it is already checked in
    // `determine_ssz_attestation_len`, however it is checked here again for additional safety
    // against panics.
    match full_ssz.get(index..end) {
        None => Err(AttestationSplitError::TooShort),
        Some(slice) => Ok((slice, end)),
    }
}

/// Given some SSZ, assume that a serialized `AttestationRecord` begins at the `index` position and
/// attempt to find the length (in bytes) of that serialized `AttestationRecord`.
///
/// This function does not perform validation on the `AttestationRecord`. It is very likely that
/// given some sufficiently long non-`AttestationRecord` bytes it will not raise an error.
fn determine_ssz_attestation_len(
    full_ssz: &[u8],
    index: usize,
) -> Result<usize, AttestationSplitError> {
    if full_ssz.len() < MIN_SSZ_ATTESTION_RECORD_LENGTH {
        return Err(AttestationSplitError::TooShort);
    }

    let data_struct_end = index + SSZ_ATTESTION_DATA_LENGTH;

    // Determine the end of the first bitfield.
    let participation_bitfield_len = decode_length(full_ssz, data_struct_end, LENGTH_BYTES)
        .map_err(|_| AttestationSplitError::TooShort)?;
    let participation_bitfield_end = data_struct_end + LENGTH_BYTES + participation_bitfield_len;

    // Determine the end of the second bitfield.
    let custody_bitfield_len = decode_length(full_ssz, participation_bitfield_end, LENGTH_BYTES)
        .map_err(|_| AttestationSplitError::TooShort)?;
    let custody_bitfield_end = participation_bitfield_end + LENGTH_BYTES + custody_bitfield_len;

    // Determine the very end of the AttestationRecord.
    let agg_sig_end = custody_bitfield_end + LENGTH_BYTES + BLS_AGG_SIG_BYTE_SIZE;

    if agg_sig_end > full_ssz.len() {
        Err(AttestationSplitError::TooShort)
    } else {
        Ok(agg_sig_end - index)
    }
}

#[cfg(test)]
mod tests {
    use super::super::bls::AggregateSignature;
    use super::super::ssz::{Decodable, SszStream};
    use super::super::types::{AttestationData, AttestationRecord, Bitfield, Hash256};
    use super::*;

    fn get_two_records() -> Vec<AttestationRecord> {
        let a = AttestationRecord {
            data: AttestationData {
                slot: 7,
                shard: 9,
                beacon_block_hash: Hash256::from("a_beacon".as_bytes()),
                epoch_boundary_hash: Hash256::from("a_epoch".as_bytes()),
                shard_block_hash: Hash256::from("a_shard".as_bytes()),
                latest_crosslink_hash: Hash256::from("a_xlink".as_bytes()),
                justified_slot: 19,
                justified_block_hash: Hash256::from("a_justified".as_bytes()),
            },
            participation_bitfield: Bitfield::from_bytes(&vec![17; 42][..]),
            custody_bitfield: Bitfield::from_bytes(&vec![255; 12][..]),
            aggregate_sig: AggregateSignature::new(),
        };
        let b = AttestationRecord {
            data: AttestationData {
                slot: 9,
                shard: 7,
                beacon_block_hash: Hash256::from("b_beacon".as_bytes()),
                epoch_boundary_hash: Hash256::from("b_epoch".as_bytes()),
                shard_block_hash: Hash256::from("b_shard".as_bytes()),
                latest_crosslink_hash: Hash256::from("b_xlink".as_bytes()),
                justified_slot: 15,
                justified_block_hash: Hash256::from("b_justified".as_bytes()),
            },
            participation_bitfield: Bitfield::from_bytes(&vec![1; 42][..]),
            custody_bitfield: Bitfield::from_bytes(&vec![11; 3][..]),
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
        let (decoded_a, _) = AttestationRecord::ssz_decode(a_ssz, 0).unwrap();
        assert_eq!(a, decoded_a);

        /*
         * Test split two
         */
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&a);
        ssz_stream.append(&b);
        let ssz = ssz_stream.drain();
        let ssz_vec = split_all_attestations(&ssz, 0).unwrap();
        let (decoded_a, _) = AttestationRecord::ssz_decode(ssz_vec[0], 0).unwrap();
        let (decoded_b, _) = AttestationRecord::ssz_decode(ssz_vec[1], 0).unwrap();
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
