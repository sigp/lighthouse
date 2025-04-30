pub mod altair;
pub mod bellatrix;
pub mod capella;
pub mod deneb;
pub mod eip7805;
pub mod electra;
pub mod fulu;

pub use altair::upgrade_to_altair;
pub use bellatrix::upgrade_to_bellatrix;
pub use capella::upgrade_to_capella;
pub use deneb::upgrade_to_deneb;
pub use eip7805::upgrade_to_eip7805;
pub use electra::upgrade_to_electra;
pub use fulu::upgrade_to_fulu;
