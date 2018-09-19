use super::{
    LENGTH_BYTES,
    MAX_LIST_SIZE,
};

#[derive(Debug)]
pub enum EncodeError {
    ListTooLong,
}

pub trait Encodable {
    fn ssz_append(&self, s: &mut SszStream);
}

/// Provides a buffer for appending ssz-encodable values.
///
/// Use the `append()` fn to add a value to a list, then use
/// the `drain()` method to consume the struct and return the
/// ssz encoded bytes.
pub struct SszStream {
    buffer: Vec<u8>
}

impl SszStream {
    /// Create a new, empty stream for writing ssz values.
    pub fn new() -> Self {
        SszStream {
            buffer: Vec::new()
        }
    }

    /// Append some ssz encodable value to the stream.
    pub fn append<E>(&mut self, value: &E) -> &mut Self
        where E: Encodable
    {
        value.ssz_append(self);
        self
    }

    /// Append some ssz encoded bytes to the stream.
    ///
    /// The length of the supplied bytes will be concatenated
    /// to the stream before the supplied bytes.
    pub fn append_encoded_val(&mut self, vec: &Vec<u8>) {
        self.buffer.extend_from_slice(
            &encode_length(vec.len(),
            LENGTH_BYTES));
        self.buffer.extend_from_slice(&vec);
    }

    /// Append some ssz encoded bytes to the stream without calculating length
    ///
    /// The raw bytes will be concatenated to the stream.
    pub fn append_encoded_raw(&mut self, vec: &Vec<u8>) {
        self.buffer.extend_from_slice(&vec);
    }

    /// Append some vector (list) of encodable values to the stream.
    ///
    /// The length of the list will be concatenated to the stream, then
    /// each item in the vector will be encoded and concatenated.
    pub fn append_vec<E>(&mut self, vec: &Vec<E>)
        -> Result<(), EncodeError>
        where E: Encodable
    {
        let mut list_stream = SszStream::new();
        for item in vec {
            item.ssz_append(&mut list_stream);
        }
        let list_ssz = list_stream.drain();
        if list_ssz.len() <= MAX_LIST_SIZE {
            self.append_encoded_val(&list_ssz);
            Ok(())
        } else {
            Err(EncodeError::ListTooLong)
        }
    }

    /// Consume the stream and return the underlying bytes.
    pub fn drain(self) -> Vec<u8> {
        self.buffer
    }
}

/// Encode some length into a ssz size prefix.
///
/// The ssz size prefix is 4 bytes, which is treated as a continuious
/// 32bit big-endian integer.
pub fn encode_length(len: usize, length_bytes: usize) -> Vec<u8> {
    assert!(length_bytes > 0);  // For sanity
    assert!((len as usize) < 2usize.pow(length_bytes as u32 * 8));
    let mut header: Vec<u8> = vec![0; length_bytes];
    for i in 0..length_bytes {
        let offset = (length_bytes - i - 1) * 8;
        header[i] = ((len >> offset) & 0xff) as u8;
    };
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
        assert_eq!(
            encode_length(0, LENGTH_BYTES),
            vec![0; 4]
        );
        assert_eq!(
            encode_length(1, LENGTH_BYTES),
            vec![0, 0, 0, 1]
        );
        assert_eq!(
            encode_length(255, LENGTH_BYTES),
            vec![0, 0, 0, 255]
        );
        assert_eq!(
            encode_length(256, LENGTH_BYTES),
            vec![0, 0, 1, 0]
        );
        assert_eq!(
            encode_length(4294967295, LENGTH_BYTES),  // 2^(3*8) - 1
            vec![255, 255, 255, 255]
        );
    }

    #[test]
    #[should_panic]
    fn test_encode_length_4_bytes_panic() {
        encode_length(4294967296, LENGTH_BYTES);  // 2^(3*8)
    }

    #[test]
    fn test_encode_list() {
        let test_vec: Vec<u16> = vec![256; 12];
        let mut stream = SszStream::new();
        stream.append_vec(&test_vec).unwrap();
        let ssz = stream.drain();

        assert_eq!(ssz.len(), 4 + (12 * 2));
        assert_eq!(ssz[0..4], *vec![0, 0, 0, 24]);
        assert_eq!(ssz[4..6], *vec![1, 0]);
    }
}
