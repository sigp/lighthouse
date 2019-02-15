use super::LENGTH_BYTES;

pub trait Encodable {
    fn ssz_append(&self, s: &mut SszStream);
}

/// Provides a buffer for appending ssz-encodable values.
///
/// Use the `append()` fn to add a value to a list, then use
/// the `drain()` method to consume the struct and return the
/// ssz encoded bytes.
#[derive(Default)]
pub struct SszStream {
    buffer: Vec<u8>,
}

impl SszStream {
    /// Create a new, empty stream for writing ssz values.
    pub fn new() -> Self {
        SszStream { buffer: Vec::new() }
    }

    /// Append some ssz encodable value to the stream.
    pub fn append<E>(&mut self, value: &E) -> &mut Self
    where
        E: Encodable,
    {
        value.ssz_append(self);
        self
    }

    /// Append some ssz encoded bytes to the stream.
    ///
    /// The length of the supplied bytes will be concatenated
    /// to the stream before the supplied bytes.
    pub fn append_encoded_val(&mut self, vec: &[u8]) {
        self.buffer
            .extend_from_slice(&encode_length(vec.len(), LENGTH_BYTES));
        self.buffer.extend_from_slice(&vec);
    }

    /// Append some ssz encoded bytes to the stream without calculating length
    ///
    /// The raw bytes will be concatenated to the stream.
    pub fn append_encoded_raw(&mut self, vec: &[u8]) {
        self.buffer.extend_from_slice(&vec);
    }

    /// Append some vector (list) of encodable values to the stream.
    ///
    /// The length of the list will be concatenated to the stream, then
    /// each item in the vector will be encoded and concatenated.
    pub fn append_vec<E>(&mut self, vec: &[E])
    where
        E: Encodable,
    {
        let mut list_stream = SszStream::new();
        for item in vec {
            item.ssz_append(&mut list_stream);
        }
        self.append_encoded_val(&list_stream.drain());
    }

    /// Consume the stream and return the underlying bytes.
    pub fn drain(self) -> Vec<u8> {
        self.buffer
    }
}

/// Encode some length into a ssz size prefix.
///
/// The ssz size prefix is 4 bytes, which is treated as a continuious
/// 32bit little-endian integer.
pub fn encode_length(len: usize, length_bytes: usize) -> Vec<u8> {
    assert!(length_bytes > 0); // For sanity
    assert!((len as usize) < 2usize.pow(length_bytes as u32 * 8));
    let mut header: Vec<u8> = vec![0; length_bytes];
    for (i, header_byte) in header.iter_mut().enumerate() {
        let offset = (length_bytes - (length_bytes - i)) * 8;
        *header_byte = ((len >> offset) & 0xff) as u8;
    }
    header
}

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
