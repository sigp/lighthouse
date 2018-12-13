use super::attestation_data::SSZ_ATTESTION_DATA_LENGTH;
use super::bls::{AggregateSignature, BLS_AGG_SIG_BYTE_SIZE};
use super::ssz::{decode_ssz_list, Decodable, DecodeError, Encodable, SszStream, LENGTH_BYTES};
use super::{AttestationData, Bitfield};

pub const MIN_SSZ_ATTESTION_RECORD_LENGTH: usize = {
    SSZ_ATTESTION_DATA_LENGTH +     // data
    5 +                                 // participation_bitfield (assuming 1 byte of bitfield)
    5 +                                 // custody_bitfield (assuming 1 byte of bitfield)
    LENGTH_BYTES + BLS_AGG_SIG_BYTE_SIZE // aggregate sig
};

#[derive(Debug, Clone, PartialEq)]
pub struct Attestation {
    pub data: AttestationData,
    pub participation_bitfield: Bitfield,
    pub custody_bitfield: Bitfield,
    pub aggregate_sig: AggregateSignature,
}

impl Encodable for Attestation {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.data);
        s.append(&self.participation_bitfield);
        s.append(&self.custody_bitfield);
        s.append_vec(&self.aggregate_sig.as_bytes());
    }
}

impl Decodable for Attestation {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (data, i) = AttestationData::ssz_decode(bytes, i)?;
        let (participation_bitfield, i) = Bitfield::ssz_decode(bytes, i)?;
        let (custody_bitfield, i) = Bitfield::ssz_decode(bytes, i)?;
        let (agg_sig_bytes, i) = decode_ssz_list(bytes, i)?;
        let aggregate_sig =
            AggregateSignature::from_bytes(&agg_sig_bytes).map_err(|_| DecodeError::TooShort)?; // also could be TooLong

        let attestation_record = Self {
            data,
            participation_bitfield,
            custody_bitfield,
            aggregate_sig,
        };
        Ok((attestation_record, i))
    }
}

impl Attestation {
    pub fn zero() -> Self {
        Self {
            data: AttestationData::zero(),
            participation_bitfield: Bitfield::new(),
            custody_bitfield: Bitfield::new(),
            aggregate_sig: AggregateSignature::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz::ssz_encode;
    use super::*;

    #[test]
    pub fn test_attestation_record_min_ssz_length() {
        let ar = Attestation::zero();
        let ssz = ssz_encode(&ar);

        assert_eq!(ssz.len(), MIN_SSZ_ATTESTION_RECORD_LENGTH);
    }

    #[test]
    pub fn test_attestation_record_ssz_round_trip() {
        let original = Attestation {
            data: AttestationData::zero(),
            participation_bitfield: Bitfield::from_bytes(&vec![17; 42][..]),
            custody_bitfield: Bitfield::from_bytes(&vec![18; 12][..]),
            aggregate_sig: AggregateSignature::new(),
        };

        let ssz = ssz_encode(&original);
        let (decoded, _) = Attestation::ssz_decode(&ssz, 0).unwrap();

        assert_eq!(original, decoded);
    }
}
