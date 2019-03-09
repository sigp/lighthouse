use crate::*;
use ssz::SignedRoot;

pub struct TestingTransferBuilder {
    transfer: Transfer,
}

impl TestingTransferBuilder {
    pub fn new(from: u64, to: u64, amount: u64, slot: Slot) -> Self {
        let keypair = Keypair::random();

        let mut transfer = Transfer {
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

    pub fn sign(&mut self, keypair: Keypair, fork: &Fork, spec: &ChainSpec) {
        self.transfer.pubkey = keypair.pk;
        let message = self.transfer.signed_root();
        let epoch = self.transfer.slot.epoch(spec.slots_per_epoch);
        let domain = spec.get_domain(epoch, Domain::Transfer, fork);

        self.transfer.signature = Signature::new(&message, domain, &keypair.sk);
    }

    pub fn build(self) -> Transfer {
        self.transfer
    }
}
