use super::ssz::{Decodable, DecodeError, Encodable, SszStream};
use super::SlashableVoteData;

#[derive(Debug, PartialEq, Clone, Default)]
pub struct CasperSlashing {
    pub slashable_vote_data_1: SlashableVoteData,
    pub slashable_vote_data_2: SlashableVoteData,
}

impl Encodable for CasperSlashing {
    fn ssz_append(&self, s: &mut SszStream) {
        s.append(&self.slashable_vote_data_1);
        s.append(&self.slashable_vote_data_1);
    }
}

impl Decodable for CasperSlashing {
    fn ssz_decode(bytes: &[u8], i: usize) -> Result<(Self, usize), DecodeError> {
        let (slashable_vote_data_1, i) = <_>::ssz_decode(bytes, i)?;
        let (slashable_vote_data_2, i) = <_>::ssz_decode(bytes, i)?;

        Ok((
            CasperSlashing {
                slashable_vote_data_1,
                slashable_vote_data_2,
            },
            i,
        ))
    }
}
