use super::ssz::{ Encodable, SszStream };


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
    pub kind: SpecialRecordKind,
    pub data: Vec<u8>,
}

impl SpecialRecord {
    pub fn logout(data: &[u8]) -> Self {
        Self {
            kind: SpecialRecordKind::Logout,
            data: data.to_vec(),
        }
    }

    pub fn casper_slashing(data: &[u8]) -> Self {
        Self {
            kind: SpecialRecordKind::CasperSlashing,
            data: data.to_vec(),
        }
    }

    pub fn randao_change(data: &[u8]) -> Self {
        Self {
            kind: SpecialRecordKind::RandaoChange,
            data: data.to_vec(),
        }
    }
}

impl Encodable for SpecialRecord {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.kind);
        s.append_vec(&self.data);
    }
}

impl Encodable for SpecialRecordKind {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&(*self as u8));
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_special_record_ssz() {
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
}
