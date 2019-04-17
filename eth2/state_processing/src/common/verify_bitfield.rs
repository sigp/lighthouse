use types::*;

/// Verify ``bitfield`` against the ``committee_size``.
///
/// Is title `verify_bitfield` in spec.
///
/// Spec v0.5.1
pub fn verify_bitfield_length(bitfield: &Bitfield, committee_size: usize) -> bool {
    if bitfield.num_bytes() != ((committee_size + 7) / 8) {
        return false;
    }

    for i in committee_size..(bitfield.num_bytes() * 8) {
        if bitfield.get(i).unwrap_or(false) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bitfield_length() {
        assert_eq!(
            verify_bitfield_length(&Bitfield::from_bytes(&[0b0000_0001]), 4),
            true
        );

        assert_eq!(
            verify_bitfield_length(&Bitfield::from_bytes(&[0b0001_0001]), 4),
            false
        );

        assert_eq!(
            verify_bitfield_length(&Bitfield::from_bytes(&[0b0000_0000]), 4),
            true
        );

        assert_eq!(
            verify_bitfield_length(&Bitfield::from_bytes(&[0b1000_0000]), 8),
            true
        );

        assert_eq!(
            verify_bitfield_length(&Bitfield::from_bytes(&[0b1000_0000, 0b0000_0000]), 16),
            true
        );

        assert_eq!(
            verify_bitfield_length(&Bitfield::from_bytes(&[0b1000_0000, 0b0000_0000]), 15),
            false
        );

        assert_eq!(
            verify_bitfield_length(&Bitfield::from_bytes(&[0b0000_0000, 0b0000_0000]), 8),
            false
        );

        assert_eq!(
            verify_bitfield_length(
                &Bitfield::from_bytes(&[0b0000_0000, 0b0000_0000, 0b0000_0000]),
                8
            ),
            false
        );

        assert_eq!(
            verify_bitfield_length(
                &Bitfield::from_bytes(&[0b0000_0000, 0b0000_0000, 0b0000_0000]),
                24
            ),
            true
        );
    }
}
