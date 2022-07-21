/// This value is an application index of 0 with the bitmask applied (so it's equivalent to the bit mask).
/// Little endian hex: 0x00000001, Binary: 1000000000000000000000000
pub const APPLICATION_DOMAIN_BUILDER: u32 = 16777216;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ApplicationDomain {
    Builder,
}

impl ApplicationDomain {
    pub fn get_domain_constant(&self) -> u32 {
        match self {
            ApplicationDomain::Builder => APPLICATION_DOMAIN_BUILDER,
        }
    }
}
