//! A collection of types used to pass data across the rest HTTP API.
//!
//! This is primarily used by the validator client and the beacon node rest API.

mod api_error;
mod beacon;
mod consensus;
mod handler;
mod node;
mod validator;

pub use api_error::{ApiError, ApiResult};
pub use beacon::{
    BlockResponse, CanonicalHeadResponse, Committee, HeadBeaconBlock, StateResponse,
    ValidatorRequest, ValidatorResponse,
};
pub use consensus::{IndividualVote, IndividualVotesRequest, IndividualVotesResponse};
pub use handler::{ApiEncodingFormat, Handler};
pub use node::{Health, SyncingResponse, SyncingStatus};
pub use validator::{
    ValidatorDutiesRequest, ValidatorDuty, ValidatorDutyBytes, ValidatorSubscription,
};
