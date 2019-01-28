use crate::Attestation;

impl Attestation {
    pub fn signable_message(&self, custody_bit: bool) -> Vec<u8> {
        self.data.signable_message(custody_bit)
    }
}
