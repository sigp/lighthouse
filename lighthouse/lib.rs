#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate slog_async;
extern crate ssz;
extern crate clap;
extern crate network_libp2p;
extern crate futures;

#[macro_use]
#[allow(dead_code)]
pub mod utils;
#[allow(dead_code)]
pub mod bls;
#[allow(dead_code)]
pub mod db;
pub mod client;
#[allow(dead_code)]
pub mod state;
#[allow(dead_code)]
mod sync;
mod config;
