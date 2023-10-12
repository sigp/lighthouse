use ssz::{Decode, Encode};
use ssz_derive::Encode;

#[derive(Debug, Clone, PartialEq, Encode)]
#[ssz(struct_behaviour = "transparent")]
pub struct RuntimeVariableList<T: Encode> {
    vec: Vec<T>,
    #[ssz(skip_serializing, skip_deserializing)]
    max_len: usize,
}

impl<T: Encode + Decode + Clone> RuntimeVariableList<T> {
    pub fn new(vec: Vec<T>, max_len: usize) -> Result<Self, ssz_types::Error> {
        if vec.len() <= max_len {
            Ok(Self { vec, max_len })
        } else {
            Err(ssz_types::Error::OutOfBounds {
                i: vec.len(),
                len: max_len,
            })
        }
    }

    pub fn from_vec(mut vec: Vec<T>, max_len: usize) -> Self {
        vec.truncate(max_len);

        Self { vec, max_len }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.vec.clone()
    }

    pub fn as_slice(&self) -> &[T] {
        self.vec.as_slice()
    }

    pub fn len(&self) -> usize {
        self.vec.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }

    pub fn from_ssz_bytes(bytes: &[u8], max_len: usize) -> Result<Self, ssz::DecodeError> {
        let vec = if bytes.is_empty() {
            vec![]
        } else {
            ssz::decode_list_of_variable_length_items(bytes, Some(max_len))?
        };
        Ok(Self { vec, max_len })
    }
}
