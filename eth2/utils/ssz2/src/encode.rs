use super::*;

mod impls;

pub trait Encodable {
    fn as_ssz_bytes(&self) -> Vec<u8>;

    fn is_ssz_fixed_len() -> bool;

    /// The number of bytes this object occupies in the fixed-length portion of the SSZ bytes.
    ///
    /// By default, this is set to `BYTES_PER_LENGTH_OFFSET` which is suitable for variable length
    /// objects, but not fixed-length objects. Fixed-length objects _must_ return a value which
    /// represents their length.
    fn ssz_fixed_len() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
}

/// Provides a buffer for appending SSZ values.
#[derive(Default)]
pub struct SszStream {
    fixed: Vec<u8>,
    variable: Vec<u8>,
}

impl SszStream {
    /// Create a new, empty stream for writing SSZ values.
    pub fn new() -> Self {
        SszStream {
            fixed: vec![],
            variable: vec![],
        }
    }

    /// Append some item to the stream.
    pub fn append<T: Encodable>(&mut self, item: &T) {
        let mut bytes = item.as_ssz_bytes();

        if T::is_ssz_fixed_len() {
            self.fixed.append(&mut bytes);
        } else {
            self.fixed.append(&mut encode_length(bytes.len()));
            self.variable.append(&mut bytes);
        }
    }

    /// Append the variable-length bytes to the fixed-length bytes and return the result.
    pub fn drain(mut self) -> Vec<u8> {
        self.fixed.append(&mut self.variable);

        self.fixed
    }
}

/// Encode `len` as a little-endian byte vec of `BYTES_PER_LENGTH_OFFSET` length.
///
/// If `len` is larger than `2 ^ BYTES_PER_LENGTH_OFFSET`, a `debug_assert` is raised.
pub fn encode_length(len: usize) -> Vec<u8> {
    debug_assert!(len <= MAX_LENGTH_VALUE);

    len.to_le_bytes()[0..BYTES_PER_LENGTH_OFFSET].to_vec()
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn test_encode_length_0_bytes_panic() {
        encode_length(0, 0);
    }

    #[test]
    fn test_encode_length_4_bytes() {
        assert_eq!(encode_length(0, LENGTH_BYTES), vec![0; 4]);
        assert_eq!(encode_length(1, LENGTH_BYTES), vec![1, 0, 0, 0]);
        assert_eq!(encode_length(255, LENGTH_BYTES), vec![255, 0, 0, 0]);
        assert_eq!(encode_length(256, LENGTH_BYTES), vec![0, 1, 0, 0]);
        assert_eq!(
            encode_length(4294967295, LENGTH_BYTES), // 2^(3*8) - 1
            vec![255, 255, 255, 255]
        );
    }

    #[test]
    fn test_encode_lower_length() {
        assert_eq!(encode_length(0, LENGTH_BYTES - 2), vec![0; 2]);
        assert_eq!(encode_length(1, LENGTH_BYTES - 2), vec![1, 0]);
    }

    #[test]
    fn test_encode_higher_length() {
        assert_eq!(encode_length(0, LENGTH_BYTES + 2), vec![0; 6]);
        assert_eq!(encode_length(1, LENGTH_BYTES + 2), vec![1, 0, 0, 0, 0, 0]);
    }

    #[test]
    #[should_panic]
    fn test_encode_length_4_bytes_panic() {
        encode_length(4294967296, LENGTH_BYTES); // 2^(3*8)
    }

    #[test]
    fn test_encode_list() {
        let test_vec: Vec<u16> = vec![256; 12];
        let mut stream = SszStream::new();
        stream.append_vec(&test_vec);
        let ssz = stream.drain();

        assert_eq!(ssz.len(), LENGTH_BYTES + (12 * 2));
        assert_eq!(ssz[0..4], *vec![24, 0, 0, 0]);
        assert_eq!(ssz[4..6], *vec![0, 1]);
    }

    #[test]
    fn test_encode_mixed_prefixed() {
        let test_vec: Vec<u16> = vec![100, 200];
        let test_value: u8 = 5;

        let mut stream = SszStream::new();
        stream.append_vec(&test_vec);
        stream.append(&test_value);
        let ssz = stream.drain();

        assert_eq!(ssz.len(), LENGTH_BYTES + (2 * 2) + 1);
        assert_eq!(ssz[0..4], *vec![4, 0, 0, 0]);
        assert_eq!(ssz[4..6], *vec![100, 0]);
        assert_eq!(ssz[6..8], *vec![200, 0]);
        assert_eq!(ssz[8], 5);
    }

    #[test]
    fn test_encode_mixed_postfixed() {
        let test_value: u8 = 5;
        let test_vec: Vec<u16> = vec![100, 200];

        let mut stream = SszStream::new();
        stream.append(&test_value);
        stream.append_vec(&test_vec);
        let ssz = stream.drain();

        assert_eq!(ssz.len(), 1 + LENGTH_BYTES + (2 * 2));
        assert_eq!(ssz[0], 5);
        assert_eq!(ssz[1..5], *vec![4, 0, 0, 0]);
        assert_eq!(ssz[5..7], *vec![100, 0]);
        assert_eq!(ssz[7..9], *vec![200, 0]);
    }
}
*/
