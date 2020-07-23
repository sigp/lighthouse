use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// To allow serde to encode/decode byte arrays from HEX ASCII strings.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl Into<String> for HexBytes {
    fn into(self) -> String {
        hex::encode(self.0)
    }
}

impl TryFrom<String> for HexBytes {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        // Left-pad with a zero if there is not an even number of hex digits to ensure
        // `hex::decode` doesn't return an error.
        let s = if s.len() % 2 != 0 {
            format!("0{}", s)
        } else {
            s
        };

        hex::decode(s)
            .map(Self)
            .map_err(|e| format!("Invalid hex: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(json: &str) -> Vec<u8> {
        serde_json::from_str::<HexBytes>(&format!("\"{}\"", json))
            .expect("should decode json")
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn odd_hex_bytes() {
        let empty: Vec<u8> = vec![];

        assert_eq!(decode(""), empty, "should decode nothing");
        assert_eq!(decode("00"), vec![0], "should decode 00");
        assert_eq!(decode("0"), vec![0], "should decode 0");
        assert_eq!(decode("01"), vec![1], "should decode 01");
        assert_eq!(decode("1"), vec![1], "should decode 1");
        assert_eq!(decode("0101"), vec![1, 1], "should decode 0101");
        assert_eq!(decode("101"), vec![1, 1], "should decode 101");
    }
}
