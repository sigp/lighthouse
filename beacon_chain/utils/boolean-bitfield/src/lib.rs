extern crate bit_vec;
extern crate ssz;

#[cfg(test)]
extern crate rand;

use bit_vec::BitVec;

/// A BooleanBitfield represents a set of booleans compactly stored as a vector of bits.
#[derive(Debug, Clone, PartialEq)]
pub struct BooleanBitfield(BitVec);

/// Error represents some reason a request against a bitfield was not satisfied
#[derive(Debug)]
pub enum Error {
    /// OutOfBounds refers to indexing into a bitfield where no bits exist; returns the illegal index and the current size of the bitfield, respectively
    OutOfBounds(usize, usize),
}

impl BooleanBitfield {
    /// Create a new bitfield with a length of zero.
    pub fn new() -> Self {
        Self { 0: BitVec::new() }
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
    /// Returns the previous value if successful.
    /// If the index is out of bounds, we return an error to that extent.
    pub fn set(&mut self, i: usize, value: bool) -> Result<bool, Error> {
        let previous = self.get(i)?;
        self.0.set(i, value);
        Ok(previous)
    }

    /// Returns the index of the highest set bit. Some(n) if some bit is set, None otherwise.
    pub fn highest_set_bit(&self) -> Option<usize> {
        self.0.iter().rposition(|bit| bit)
    }

    /// Returns the number of bits in this bitfield.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the number of `1` bits in the bitfield
    pub fn num_set_bits(&self) -> usize {
        self.0.iter().filter(|&bit| bit).count()
    }

    /// Returns a vector of bytes representing the bitfield
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
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
            let field = BooleanBitfield::from_bytes(&bytes[(index + 4)..(index + len + 4)]);
            let index = index + ssz::LENGTH_BYTES + len;
            Ok((field, index))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_bitfield() {
        let mut field = BooleanBitfield::new();

        for _ in 0..100 {
            let index: usize = rand::random();
            assert!(field.get(index).is_err());
            assert!(field.set(index, rand::random()).is_err())
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
        assert_eq!(field.len(), 0);
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
        assert_eq!(field.to_bytes(), vec![]);
    }
}
