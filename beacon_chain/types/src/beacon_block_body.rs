use super::ssz::{decode_ssz_list, Decodable, DecodeError, Encodable, SszStream};
use super::{Attestation, CasperSlashing, Deposit, Exit, ProposerSlashing};

#[derive(Debug, PartialEq, Clone, Default)]
pub struct BeaconBlockBody {
    pub proposer_slashings: Vec<ProposerSlashing>,
    pub casper_slashings: Vec<CasperSlashing>,
    pub attestations: Vec<Attestation>,
    pub deposits: Vec<Deposit>,
    pub exits: Vec<Exit>,
}

impl Encodable for BeaconBlockBody {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append_vec(&self.proposer_slashings);
        s.append_vec(&self.casper_slashings);
        s.append_vec(&self.attestations);
        s.append_vec(&self.deposits);
        s.append_vec(&self.exits);
    }
}

impl Decodable for BeaconBlockBody {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (proposer_slashings, i) = decode_ssz_list(bytes, i)?;
        let (casper_slashings, i) = decode_ssz_list(bytes, i)?;
        let (attestations, i) = decode_ssz_list(bytes, i)?;
        let (deposits, i) = decode_ssz_list(bytes, i)?;
        let (exits, i) = decode_ssz_list(bytes, i)?;

        Ok((
            Self {
                proposer_slashings,
                casper_slashings,
                attestations,
                deposits,
                exits,
            },
            i,
        ))
    }
}
