/// This value is an application index of 0 with the bitmask applied (so it's equivalent to the bit mask).
/// Little endian hex: 0x00000001, Binary: 1000000000000000000000000
pub const APPLICATION_DOMAIN_BUILDER: u32 = 16777216;

/// `DOMAIN_REQUEST_AUTH` from builder-specs #165, for Gloas builder-API request authentication.
/// Little endian hex: 0x0B000001 (i.e. `APPLICATION_DOMAIN_BUILDER` with a `0x0B` first byte).
pub const APPLICATION_DOMAIN_REQUEST_AUTH: u32 = 16777227;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ApplicationDomain {
    /// NOTE: This domain is only used for out-of-protocol block building, DO NOT use it for Gloas/ePBS.
    Builder,
    /// Authenticates a Gloas builder-API request (`SignedRequestAuth`), per builder-specs #165.
    RequestAuth,
}

impl ApplicationDomain {
    pub fn get_domain_constant(&self) -> u32 {
        match self {
            ApplicationDomain::Builder => APPLICATION_DOMAIN_BUILDER,
            ApplicationDomain::RequestAuth => APPLICATION_DOMAIN_REQUEST_AUTH,
        }
    }
}
