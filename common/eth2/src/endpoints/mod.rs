//! Beacon Node API endpoint implementations.

pub mod beacon;
pub mod config;
pub mod debug;
pub mod events;
pub mod node;
pub mod validator;

use crate::client::{BeaconNodeHttpClient, Error};
use crate::mixin::{RequestAccept, ResponseOptional};
use crate::types::{Accept, EndpointVersion};
use reqwest::{Body, IntoUrl, RequestBuilder, Response, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;