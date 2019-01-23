extern crate bls;
extern crate spec;
extern crate types;

mod slashing;

pub use crate::slashing::verify_slashable_data;
