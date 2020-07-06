//! A collection of types used to pass data across the rest HTTP API.
//!
//! This is primarily used by the validator client and the beacon node rest API.

mod beacon;
mod consensus;
mod node;
mod validator;

pub use beacon::{
    BlockResponse, CanonicalHeadResponse, Committee, HeadBeaconBlock, StateResponse,
    ValidatorRequest, ValidatorResponse,
};

pub use validator::{
    ValidatorDutiesRequest, ValidatorDuty, ValidatorDutyBytes, ValidatorSubscription,
};

pub use consensus::{IndividualVote, IndividualVotesRequest, IndividualVotesResponse};

pub use node::{Health, SyncingResponse, SyncingStatus};
