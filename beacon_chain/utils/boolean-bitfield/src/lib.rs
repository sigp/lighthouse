extern crate bit_vec;
extern crate ssz;

use bit_vec::BitVec;

use std::default;

/// A BooleanBitfield represents a set of booleans compactly stored as a vector of bits.
/// The BooleanBitfield is given a fixed size during construction. Reads outside of the current size return an out-of-bounds error. Writes outside of the current size expand the size of the set.
#[derive(Debug, Clone, PartialEq)]
pub struct BooleanBitfield(BitVec);

/// Error represents some reason a request against a bitfield was not satisfied
#[derive(Debug)]
pub enum Error {
    /// OutOfBounds refers to indexing into a bitfield where no bits exist; returns the illegal index and the current size of the bitfield, respectively
    OutOfBounds(usize, usize),
}

impl BooleanBitfield {
    /// Create a new bitfield.
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a new bitfield with the given length `initial_len` and all values set to `bit`.
    pub fn from_elem(inital_len: usize, bit: bool) -> Self {
        Self {
            0: BitVec::from_elem(inital_len, bit),
        }
    }

    /// Create a new bitfield using the supplied `bytes` as input
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            0: BitVec::from_bytes(bytes),
        }
    }

    /// Read the value of a bit.
    ///
    /// If the index is in bounds, then result is Ok(value) where value is `true` if the bit is 1 and `false` if the bit is 0.
    /// If the index is out of bounds, we return an error to that extent.
    pub fn get(&self, i: usize) -> Result<bool, Error> {
        match self.0.get(i) {
            Some(value) => Ok(value),
            None => Err(Error::OutOfBounds(i, self.0.len())),
        }
    }

    /// Set the value of a bit.
    ///
    /// If the index is out of bounds, we expand the size of the underlying set to include the new index.
    /// Returns the previous value if there was one.
    pub fn set(&mut self, i: usize, value: bool) -> Option<bool> {
        let previous = match self.get(i) {
            Ok(previous) => Some(previous),
            Err(Error::OutOfBounds(_, len)) => {
                let new_len = i - len + 1;
                self.0.grow(new_len, false);
                None
            }
        };
        self.0.set(i, value);
        previous
    }

    /// Returns the index of the highest set bit. Some(n) if some bit is set, None otherwise.
    pub fn highest_set_bit(&self) -> Option<usize> {
        self.0.iter().rposition(|bit| bit)
    }

    /// Returns the number of bits in this bitfield.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the number of bytes required to represent this bitfield.
    pub fn num_bytes(&self) -> usize {
        self.to_bytes().len()
    }

    /// Returns the number of `1` bits in the bitfield
    pub fn num_set_bits(&self) -> usize {
        self.0.iter().filter(|&bit| bit).count()
    }

    /// Returns a vector of bytes representing the bitfield
    /// Note that this returns the bit layout of the underlying implementation in the `bit-vec` crate.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl default::Default for BooleanBitfield {
    /// default provides the "empty" bitfield
    /// Note: the empty bitfield is set to the `0` byte.
    fn default() -> Self {
        Self::from_elem(8, false)
    }
}

// borrowed from bit_vec crate
fn reverse_bits(byte: u8) -> u8 {
    let mut result = 0;
    for i in 0..8 {
        result = result | ((byte >> i) & 1) << (7 - i);
    }
    result
}

impl ssz::Encodable for BooleanBitfield {
    // ssz_append encodes Self according to the `ssz` spec.
    // Note that we have to flip the endianness of the encoding with `reverse_bits` to account for an implementation detail of `bit-vec` crate.
    fn ssz_append(&self, s: &mut ssz::SszStream) {
        let bytes: Vec<u8> = self
            .to_bytes()
            .iter()
            .map(|&byte| reverse_bits(byte))
            .collect();
        s.append_vec(&bytes);
    }
}

impl ssz::Decodable for BooleanBitfield {
    fn ssz_decode(bytes: &[u8], index: usize) -> Result<(Self, usize), ssz::DecodeError> {
        let len = ssz::decode::decode_length(bytes, index, ssz::LENGTH_BYTES)?;
        if (ssz::LENGTH_BYTES + len) > bytes.len() {
            return Err(ssz::DecodeError::TooShort);
        }

        if len == 0 {
            Ok((BooleanBitfield::new(), index + ssz::LENGTH_BYTES))
        } else {
            let bytes = &bytes[(index + 4)..(index + len + 4)];

            let mut field = BooleanBitfield::from_elem(0, false);
            for (byte_index, byte) in bytes.iter().enumerate() {
                for i in 0..8 {
                    let bit = byte & (1 << i);
                    if bit != 0 {
                        field.set(8 * byte_index + i, true);
                    }
                }
            }

            let index = index + ssz::LENGTH_BYTES + len;
            Ok((field, index))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::SszStream;

    #[test]
    fn test_empty_bitfield() {
        let mut field = BooleanBitfield::new();
        let original_len = field.len();

        for i in 0..100 {
            if i < original_len {
                assert!(!field.get(i).unwrap());
            } else {
                assert!(field.get(i).is_err());
            }
            let previous = field.set(i, true);
            if i < original_len {
                assert!(!previous.unwrap());
            } else {
                assert!(previous.is_none());
            }
        }
    }

    const INPUT: &[u8] = &[0b0000_0010, 0b0000_0010];

    #[test]
    fn test_get_from_bitfield() {
        let field = BooleanBitfield::from_bytes(INPUT);
        let unset = field.get(0).unwrap();
        assert!(!unset);
        let set = field.get(6).unwrap();
        assert!(set);
        let set = field.get(14).unwrap();
        assert!(set);
    }

    #[test]
    fn test_set_for_bitfield() {
        let mut field = BooleanBitfield::from_bytes(INPUT);
        let previous = field.set(10, true).unwrap();
        assert!(!previous);
        let previous = field.get(10).unwrap();
        assert!(previous);
        let previous = field.set(6, false).unwrap();
        assert!(previous);
        let previous = field.get(6).unwrap();
        assert!(!previous);
    }

    #[test]
    fn test_highest_set_bit() {
        let field = BooleanBitfield::from_bytes(INPUT);
        assert_eq!(field.highest_set_bit().unwrap(), 14);

        let field = BooleanBitfield::new();
        assert_eq!(field.highest_set_bit(), None);
    }

    #[test]
    fn test_len() {
        let field = BooleanBitfield::from_bytes(INPUT);
        assert_eq!(field.len(), 16);

        let field = BooleanBitfield::new();
        assert_eq!(field.len(), 8);
    }

    #[test]
    fn test_num_set_bits() {
        let field = BooleanBitfield::from_bytes(INPUT);
        assert_eq!(field.num_set_bits(), 2);

        let field = BooleanBitfield::new();
        assert_eq!(field.num_set_bits(), 0);
    }

    #[test]
    fn test_to_bytes() {
        let field = BooleanBitfield::from_bytes(INPUT);
        assert_eq!(field.to_bytes(), INPUT);

        let field = BooleanBitfield::new();
        assert_eq!(field.to_bytes(), vec![0]);
    }

    #[test]
    fn test_out_of_bounds() {
        let mut field = BooleanBitfield::from_bytes(INPUT);

        let out_of_bounds_index = field.len();
        assert!(field.set(out_of_bounds_index, true).is_none());
        assert!(field.len() == out_of_bounds_index + 1);
        assert!(field.get(out_of_bounds_index).unwrap());

        for i in 0..100 {
            if i <= out_of_bounds_index {
                assert!(field.set(i, true).is_some());
            } else {
                assert!(field.set(i, true).is_none());
            }
        }
    }

    #[test]
    fn test_num_bytes() {
        let field = BooleanBitfield::from_bytes(INPUT);
        assert_eq!(field.num_bytes(), 2);

        let field = BooleanBitfield::from_elem(2, true);
        assert_eq!(field.num_bytes(), 1);

        let field = BooleanBitfield::from_elem(13, true);
        assert_eq!(field.num_bytes(), 2);
    }

    #[test]
    fn test_ssz_encode() {
        let field = BooleanBitfield::from_elem(5, true);

        let mut stream = SszStream::new();
        stream.append(&field);
        assert_eq!(stream.drain(), vec![0, 0, 0, 1, 31]);

        let field = BooleanBitfield::from_elem(18, true);
        let mut stream = SszStream::new();
        stream.append(&field);
        assert_eq!(stream.drain(), vec![0, 0, 0, 3, 255, 255, 3]);
    }

    #[test]
    fn test_ssz_decode() {
        let encoded = vec![0, 0, 0, 1, 31];
        let (field, _): (BooleanBitfield, usize) = ssz::decode_ssz(&encoded, 0).unwrap();
        let expected = BooleanBitfield::from_elem(5, true);
        assert_eq!(field, expected);

        let encoded = vec![0, 0, 0, 3, 255, 255, 3];
        let (field, _): (BooleanBitfield, usize) = ssz::decode_ssz(&encoded, 0).unwrap();
        let expected = BooleanBitfield::from_elem(18, true);
        assert_eq!(field, expected);
    }
}
