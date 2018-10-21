extern crate bls;
extern crate hashing;
extern crate types;

mod inductor;

pub use inductor::{
    ValidatorInductor,
    ValidatorInductionError,
};
