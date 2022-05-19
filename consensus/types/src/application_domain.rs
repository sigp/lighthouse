#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ApplicationDomain {
    Builder,
}

impl ApplicationDomain {
    pub fn get_domain_constant(&self) -> u32 {
        match self {
            ApplicationDomain::Builder => 0,
        }
    }
}
