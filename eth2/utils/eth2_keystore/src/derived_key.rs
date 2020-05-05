use crate::DKLEN;
use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DerivedKey([u8; DKLEN as usize]);

impl DerivedKey {
    /// Instantiates `Self` with a all-zeros byte array.
    pub fn zero() -> Self {
        Self([0; DKLEN as usize])
    }

    /// Returns a mutable reference to the underlying byte array.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns the `DK_slice` bytes used for checksum comparison.
    ///
    /// ## Reference
    ///
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md#procedure
    pub fn checksum_slice(&self) -> &[u8] {
        &self.0[16..32]
    }

    /// Returns the aes-128-ctr key.
    ///
    /// Only the first 16 bytes of the decryption_key are used as the AES key.
    ///
    /// ## Reference
    ///
    /// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md#secret-decryption
    pub fn aes_key(&self) -> &[u8] {
        &self.0[0..16]
    }
}
