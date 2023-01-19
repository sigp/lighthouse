pub mod altair;
pub mod capella;
pub mod merge;
pub mod verge;

pub use altair::upgrade_to_altair;
pub use capella::upgrade_to_capella;
pub use merge::upgrade_to_bellatrix;
pub use verge::upgrade_to_verge;
