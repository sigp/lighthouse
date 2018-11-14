use super::ssz::{Decodable, DecodeError, Encodable, SszStream};

/// The value of the "type" field of SpecialRecord.
///
/// Note: this value must serialize to a u8 and therefore must not be greater than 255.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum SpecialRecordKind {
    Logout = 0,
    CasperSlashing = 1,
    RandaoChange = 2,
}

/// The structure used in the `BeaconBlock.specials` field.
#[derive(Debug, PartialEq, Clone)]
pub struct SpecialRecord {
    pub kind: u8,
    pub data: Vec<u8>,
}

impl SpecialRecord {
    pub fn logout(data: &[u8]) -> Self {
        Self {
            kind: SpecialRecordKind::Logout as u8,
            data: data.to_vec(),
        }
    }

    pub fn casper_slashing(data: &[u8]) -> Self {
        Self {
            kind: SpecialRecordKind::CasperSlashing as u8,
            data: data.to_vec(),
        }
    }

    pub fn randao_change(data: &[u8]) -> Self {
        Self {
            kind: SpecialRecordKind::RandaoChange as u8,
            data: data.to_vec(),
        }
    }

    /// Match `self.kind` to a `SpecialRecordKind`.
    ///
    /// Returns `None` if `self.kind` is an unknown value.
    pub fn resolve_kind(&self) -> Option<SpecialRecordKind> {
        match self.kind {
            x if x == SpecialRecordKind::Logout as u8 => Some(SpecialRecordKind::Logout),
            x if x == SpecialRecordKind::CasperSlashing as u8 => {
                Some(SpecialRecordKind::CasperSlashing)
            }
            x if x == SpecialRecordKind::RandaoChange as u8 => {
                Some(SpecialRecordKind::RandaoChange)
            }
            _ => None,
        }
    }
}

impl Encodable for SpecialRecord {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.kind);
        s.append_vec(&self.data);
    }
}

impl Decodable for SpecialRecord {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (kind, i) = u8::ssz_decode(bytes, i)?;
        let (data, i) = Decodable::ssz_decode(bytes, i)?;
        Ok((SpecialRecord { kind, data }, i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_special_record_ssz_encode() {
        let s = SpecialRecord::logout(&vec![]);
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&s);
        let ssz = ssz_stream.drain();
        assert_eq!(ssz, vec![0, 0, 0, 0, 0]);

        let s = SpecialRecord::casper_slashing(&vec![]);
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&s);
        let ssz = ssz_stream.drain();
        assert_eq!(ssz, vec![1, 0, 0, 0, 0]);

        let s = SpecialRecord::randao_change(&vec![]);
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&s);
        let ssz = ssz_stream.drain();
        assert_eq!(ssz, vec![2, 0, 0, 0, 0]);

        let s = SpecialRecord::randao_change(&vec![42, 43, 44]);
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&s);
        let ssz = ssz_stream.drain();
        assert_eq!(ssz, vec![2, 0, 0, 0, 3, 42, 43, 44]);
    }

    #[test]
    pub fn test_special_record_ssz_encode_decode() {
        let s = SpecialRecord::randao_change(&vec![13, 16, 14]);
        let mut ssz_stream = SszStream::new();
        ssz_stream.append(&s);
        let ssz = ssz_stream.drain();
        let (s_decoded, _) = SpecialRecord::ssz_decode(&ssz, 0).unwrap();
        assert_eq!(s, s_decoded);
    }

    #[test]
    pub fn test_special_record_resolve_kind() {
        let s = SpecialRecord::logout(&vec![]);
        assert_eq!(s.resolve_kind(), Some(SpecialRecordKind::Logout));

        let s = SpecialRecord::casper_slashing(&vec![]);
        assert_eq!(s.resolve_kind(), Some(SpecialRecordKind::CasperSlashing));

        let s = SpecialRecord::randao_change(&vec![]);
        assert_eq!(s.resolve_kind(), Some(SpecialRecordKind::RandaoChange));

        let s = SpecialRecord {
            kind: 88,
            data: vec![],
        };
        assert_eq!(s.resolve_kind(), None);
    }
}
