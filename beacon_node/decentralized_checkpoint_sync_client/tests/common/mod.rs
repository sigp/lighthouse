mod fixture;
mod policy;
mod scripted_source;

pub use fixture::FixtureFor;
pub use policy::policy;
pub use scripted_source::{Request, Response, ScriptedSource, Step};

pub type E = types::MinimalEthSpec;
pub type Fixture = FixtureFor<E>;
