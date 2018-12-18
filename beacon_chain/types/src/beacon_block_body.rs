use super::ssz::{Encodable, SszStream};
use super::{Attestation, CasperSlashing, Deposit, Exit, ProposerSlashing};

#[derive(Debug, PartialEq, Clone, Default)]
pub struct BeaconBlockBody {
    pub proposer_slashings: Vec<ProposerSlashing>,
    pub casper_slashings: Vec<CasperSlashing>,
    pub attestations: Vec<Attestation>,
    pub deposits: Vec<Deposit>,
    pub exits: Vec<Exit>,
}

/*
impl Encodable for BeaconBlockBody {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.proposer_slashings);
        s.append(&self.casper_slashings);
        s.append(&self.attestations);
        s.append(&self.deposits);
        s.append(&self.exits);
    }
}
*/
