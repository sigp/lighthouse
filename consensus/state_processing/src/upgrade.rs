pub mod altair;
pub mod bellatrix;
pub mod capella;
pub mod deneb;
pub mod electra;

pub use altair::upgrade_to_altair;
pub use bellatrix::upgrade_to_bellatrix;
pub use capella::upgrade_to_capella;
pub use deneb::upgrade_to_deneb;
pub use electra::upgrade_to_electra;
