/// A simple enum to store genesis state bytes from either static or runtime sources
#[derive(Clone, PartialEq, Debug)]
pub enum GenesisStateBytes {
    /// Genesis state included in the binary
    Slice(&'static [u8]),
    /// Genesis state loaded from filesystem at runtime
    Vec(Vec<u8>),
}

impl AsRef<[u8]> for GenesisStateBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            GenesisStateBytes::Slice(slice) => slice,
            GenesisStateBytes::Vec(vec) => vec.as_ref(),
        }
    }
}

impl From<&'static [u8]> for GenesisStateBytes {
    fn from(slice: &'static [u8]) -> Self {
        GenesisStateBytes::Slice(slice)
    }
}

impl From<Vec<u8>> for GenesisStateBytes {
    fn from(vec: Vec<u8>) -> Self {
        GenesisStateBytes::Vec(vec)
    }
}
