extern crate bls;
extern crate hashing;
extern crate spec;
extern crate types;

mod inductor;

pub use crate::inductor::{process_deposit, ValidatorInductionError};
