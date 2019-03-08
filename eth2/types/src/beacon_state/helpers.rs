use crate::*;

/// Verify ``bitfield`` against the ``committee_size``.
///
/// Is title `verify_bitfield` in spec.
///
/// Spec v0.4.0
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
