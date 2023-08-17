// Prevent compilation as part of the rest of Lighthouse.
#![cfg(any(feature = "afl", feature = "repro"))]

pub mod config;
pub mod env;
pub mod log_interceptor;
pub mod message_queue;
pub mod node;
pub mod runner;
pub mod slashing_protection;

pub use beacon_chain::hydra::{Hydra, HydraChoose};
pub use config::Config;
pub use log_interceptor::{LogConfig, LogInterceptor};
pub use message_queue::Message;
pub use node::Node;
pub use runner::Runner;
pub use slashing_protection::SlashingProtection;

use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};

pub type TestHarness<E> = BeaconChainHarness<EphemeralHarnessType<E>>;
