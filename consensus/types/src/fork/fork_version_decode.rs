use crate::fork::ForkName;

pub trait ForkVersionDecode: Sized {
    /// SSZ decode with explicit fork variant.
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError>;
}
