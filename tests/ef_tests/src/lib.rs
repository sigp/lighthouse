use types::EthSpec;

pub use case_result::CaseResult;
pub use cases::Case;
pub use doc::Doc;
pub use error::Error;
pub use yaml_decode::YamlDecode;

mod bls_setting;
mod case_result;
mod cases;
mod doc;
mod doc_header;
mod error;
mod eth_specs;
mod yaml_decode;

/// Defined where an object can return the results of some test(s) adhering to the Ethereum
/// Foundation testing format.
pub trait EfTest {
    /// Returns the results of executing one or more tests.
    fn test_results(&self) -> Vec<CaseResult>;
}
