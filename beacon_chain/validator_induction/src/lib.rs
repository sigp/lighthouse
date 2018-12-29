extern crate bls;
extern crate hashing;
extern crate types;
extern crate spec;

mod inductor;

pub use crate::inductor::{ValidatorInductionError, process_deposit};
