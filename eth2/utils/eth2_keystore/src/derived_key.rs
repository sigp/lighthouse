use crate::keystore::DKLEN;
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey([u8; DKLEN as usize]);

impl DerivedKey {
    /// Instantiates `Self` with an all-zeros byte array.
    pub fn zero() -> Self {
        Self([0; DKLEN as usize])
    }

    /// Returns a mutable reference to the underlying byte array.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns a reference to the underlying byte array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
