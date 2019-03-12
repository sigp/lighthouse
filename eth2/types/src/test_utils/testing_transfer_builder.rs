use crate::*;
use ssz::SignedRoot;

/// Builds a transfer to be used for testing purposes.
///
/// This struct should **never be used for production purposes.**
pub struct TestingTransferBuilder {
    transfer: Transfer,
}

impl TestingTransferBuilder {
    /// Instantiates a new builder.
    pub fn new(from: u64, to: u64, amount: u64, slot: Slot) -> Self {
        let keypair = Keypair::random();

        let transfer = Transfer {
            from,
            to,
            amount,
            fee: 0,
            slot,
            pubkey: keypair.pk,
            signature: Signature::empty_signature(),
        };

        Self { transfer }
    }

    /// Signs the transfer.
    ///
    /// The keypair must match that of the `from` validator index.
    pub fn sign(&mut self, keypair: Keypair, fork: &Fork, spec: &ChainSpec) {
        self.transfer.pubkey = keypair.pk;
        let message = self.transfer.signed_root();
        let epoch = self.transfer.slot.epoch(spec.slots_per_epoch);
        let domain = spec.get_domain(epoch, Domain::Transfer, fork);

        self.transfer.signature = Signature::new(&message, domain, &keypair.sk);
    }

    /// Builds the transfer, consuming the builder.
    pub fn build(self) -> Transfer {
        self.transfer
    }
}
