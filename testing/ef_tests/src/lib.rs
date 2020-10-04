use types::EthSpec;

pub use case_result::CaseResult;
pub use cases::Case;
pub use cases::{
    FinalUpdates, JustificationAndFinalization, RegistryUpdates, RewardsAndPenalties, Slashings,
};
pub use error::Error;
pub use handler::*;
pub use type_name::TypeName;

mod bls_setting;
mod case_result;
mod cases;
mod decode;
mod error;
mod handler;
mod results;
mod type_name;
