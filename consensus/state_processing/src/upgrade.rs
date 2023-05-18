pub mod altair;
pub mod capella;
pub mod deneb;
pub mod eip6110;
pub mod merge;

pub use altair::upgrade_to_altair;
pub use capella::upgrade_to_capella;
pub use deneb::upgrade_to_deneb;
pub use eip6110::upgrade_to_eip6110;
pub use merge::upgrade_to_bellatrix;
