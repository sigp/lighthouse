mod fixture;
mod scripted_source;

pub use fixture::Fixture;
pub use scripted_source::{Request, Response, ScriptedSource, Step};

pub type E = types::MinimalEthSpec;
