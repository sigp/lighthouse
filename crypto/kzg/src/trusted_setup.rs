use serde::{
    Deserialize, Serialize,
};

/// Contains the trusted setup parameters that are required to instantiate a
/// `c_kzg::KzgSettings` object.
///
/// The serialize/deserialize implementations are written according to
/// the format specified in the the ethereum consensus specs trusted setup files.
///
/// See https://github.com/ethereum/consensus-specs/blob/dev/presets/mainnet/trusted_setups/trusted_setup_4096.json
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustedSetup {
    #[serde(rename = "g1_monomial")]
    g1_monomial_points: Vec<String>,
    #[serde(rename = "g1_lagrange")]
    g1_lagrange_points: Vec<String>,
    #[serde(rename = "g2_monomial")]
    g2_monomial_points: Vec<String>,
}

impl TrustedSetup {
    pub fn g1_lagrange_points(&self) -> Vec<u8> {
        self.g1_lagrange_points.iter().flat_map(|p| {
            let stripped = strip_prefix(p);
            hex::decode(stripped).expect("expected g1 lagrange points to be well formed hex strings")
        }).collect()
    }
    pub fn g1_monomial_points(&self) -> Vec<u8> {
        self.g1_monomial_points.iter().flat_map(|p| {
            let stripped = strip_prefix(p);
            hex::decode(stripped).expect("expected g1 monomial points to be well formed hex strings")
        }).collect()
    }
    pub fn g2_monomial_points(&self) -> Vec<u8> {
        self.g2_monomial_points.iter().flat_map(|p|{
            let stripped = strip_prefix(p);
            hex::decode(stripped).expect("expected g2 monomial points to be well formed hex strings")
        }).collect()
    }
}



fn strip_prefix(s: &str) -> &str {
    if let Some(stripped) = s.strip_prefix("0x") {
        stripped
    } else {
        s
    }
}
