pub mod altair;
pub mod capella;
pub mod deneb;
pub mod electra;
pub mod merge;

pub use altair::upgrade_to_altair;
pub use capella::upgrade_to_capella;
pub use deneb::upgrade_to_deneb;
pub use electra::upgrade_to_electra;
pub use merge::upgrade_to_bellatrix;
