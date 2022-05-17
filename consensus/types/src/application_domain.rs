use crate::{ChainSpec, Domain, Hash256};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ApplicationDomain {
    BuilderRegistration,
    BuilderBid,
}

impl ApplicationDomain {
    pub fn get_domain_constant(&self) -> u32 {
        match self {
            ApplicationDomain::BuilderRegistration => 1,
            ApplicationDomain::BuilderBid => 2,
        }
    }
}
