extern crate honey_badger_split;
extern crate types;
extern crate shuffling;

pub mod delegation;

#[derive(Debug)]
pub enum TransitionError {
	InvalidInput(String),
}
